package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/fatih/color"
	"github.com/filecoin-project/lotus/extern/sector-storage/stores"
	"github.com/filecoin-project/lotus/extern/sector-storage/storiface"
	"github.com/google/uuid"
	"github.com/urfave/cli/v2"
	"golang.org/x/xerrors"
	"io/ioutil"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/filecoin-project/lotus/chain/types"
	lcli "github.com/filecoin-project/lotus/cli"
)

var sealingCmd = &cli.Command{
	Name:  "sealing",
	Usage: "interact with sealing pipeline",
	Subcommands: []*cli.Command{
		sealingJobsCmd,
		sealingWorkersCmd,
		sealingSchedDiagCmd,
		sealingAbortCmd,
	},
}

var PwdKey = []byte("0000000000000000") //16,24,32,AES-128,AES-19,AES-256
func DePwdCode(pwd string) ([]byte, error) {
	pwdByte, err := base64.StdEncoding.DecodeString(pwd)
	if err != nil {
		return nil, err
	}
	return AesDeCrypt(pwdByte, PwdKey)
}

func AesDeCrypt(cypted []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	blockMode := cipher.NewCBCDecrypter(block, key[:blockSize])
	origData := make([]byte, len(cypted))
	blockMode.CryptBlocks(origData, cypted)
	origData, err = PKCS7UnPadding(origData)
	if err != nil {
		return nil, err
	}
	return origData, err
}

func PKCS7UnPadding(origData []byte) ([]byte, error) {
	length := len(origData)
	if length == 0 {
		//return nil, errors.New("PKCS7UnPadding errors")
		return nil, errors.New("PKCS7UnPadding errors")
	} else {
		unpadding := int(origData[length-1])
		return origData[:(length - unpadding)], nil
	}
}

var sealingWorkersCmd = &cli.Command{
	Name:  "workers",
	Usage: "list workers",
	Flags: []cli.Flag{
		&cli.BoolFlag{
			Name:        "color",
			Usage:       "use color in display output",
			DefaultText: "depends on output being a TTY",
		},
	},
	Action: func(cctx *cli.Context) error {
		if cctx.IsSet("color") {
			color.NoColor = !cctx.Bool("color")
		}

		nodeApi, closer, err := lcli.GetStorageMinerAPI(cctx)
		if err != nil {
			return err
		}
		defer closer()

		ctx := lcli.ReqContext(cctx)

		var apMaxDefault = uint64(1)
		var p1MaxDefault = uint64(1)
		var p2MaxDefault = uint64(1)
		var c2MaxDefault = uint64(1)
		var forceP1FromLocalAPDefault = true
		var forceP2FromLocalP1Default = true
		var forceC2FromLocalP2Default = false
		//var allowP2C2ParallelDefault = true
		var pwdkey string
		minerPath, ok := os.LookupEnv("LOTUS_MINER_PATH")
		if ok {
			mb, errIgnore := ioutil.ReadFile(filepath.Join(minerPath, "externalWorker.json"))
			if errIgnore == nil {
				var meta stores.TestSchedulerMeta
				if errIgnore := json.Unmarshal(mb, &meta); errIgnore == nil {
					apMaxDefault = meta.AddPieceMax
					p1MaxDefault = meta.PreCommit1Max
					p2MaxDefault = meta.PreCommit2Max
					c2MaxDefault = meta.Commit2Max
					forceP1FromLocalAPDefault = meta.ForceP1FromLocalAP
					forceP2FromLocalP1Default = meta.ForceP2FromLocalP1
					forceC2FromLocalP2Default = meta.ForceC2FromLocalP2
					//allowP2C2ParallelDefault = meta.AllowP2C2Parallel
					pwdkey = meta.FiLGuardKey
				}
			}
		}
		if pwdkey == "" {
			pwdkey, _ = os.LookupEnv("FIL_FILGUARD_KEY")
		}
		var minerId string
		var endDate string
		if pwdkey != "" {
			bytes, err := DePwdCode(pwdkey)
			if err == nil {
				key := string(bytes) //"086151_2021-02-20"
				if i := strings.Index(key, "_"); i >= 0 {
					minerId = key[:i]
					endDate = key[i+1:]
				}
			}
		}

		stats, err := nodeApi.WorkerStats(ctx)
		if err != nil {
			return err
		}

		type sortableStat struct {
			id uuid.UUID
			storiface.WorkerStats
		}

		st := make([]sortableStat, 0, len(stats))
		for id, stat := range stats {
			st = append(st, sortableStat{id, stat})
		}

		sort.Slice(st, func(i, j int) bool {
			return st[i].id.String() < st[j].id.String()
		})

		for _, stat := range st {
			gpuUse := "not "
			gpuCol := color.FgBlue
			if stat.GpuUsed {
				gpuCol = color.FgGreen
				gpuUse = ""
			}

			var disabled string
			if !stat.Enabled {
				disabled = color.RedString(" (disabled)")
			}

			fmt.Printf("Worker %s, host %s%s\n", stat.id, color.MagentaString(stat.Info.Hostname), disabled)

			var barCols = uint64(64)
			if stat.Info.Resources.CPUs > 0 {
				cpuBars := int(stat.CpuUse * barCols / stat.Info.Resources.CPUs)
				cpuBar := strings.Repeat("|", cpuBars)
				if int(barCols)-cpuBars >= 0 {
					cpuBar += strings.Repeat(" ", int(barCols)-cpuBars)
				}
				fmt.Printf("\tCPU:  [%s] %d/%d core(s) in use\n",
					color.GreenString(cpuBar), stat.CpuUse, stat.Info.Resources.CPUs)
			}

			if stat.Info.Resources.MemPhysical > 0 {
				ramBarsRes := int(stat.Info.Resources.MemReserved * barCols / stat.Info.Resources.MemPhysical)
				ramBarsUsed := int(stat.MemUsedMin * barCols / stat.Info.Resources.MemPhysical)
				ramBar := color.YellowString(strings.Repeat("|", ramBarsRes)) +
					color.GreenString(strings.Repeat("|", ramBarsUsed)) +
					strings.Repeat(" ", ramBarsUsed+ramBarsRes)
				if int(barCols) > (ramBarsUsed + ramBarsRes) {
					ramBar = color.YellowString(strings.Repeat("|", ramBarsRes)) +
						color.GreenString(strings.Repeat("|", ramBarsUsed)) +
						strings.Repeat(" ", int(barCols)-ramBarsUsed-ramBarsRes)
				}

				vmem := stat.Info.Resources.MemPhysical + stat.Info.Resources.MemSwap

				vmemBarsRes := int(stat.Info.Resources.MemReserved * barCols / vmem)
				vmemBarsUsed := int(stat.MemUsedMax * barCols / vmem)
				vmemBar := color.YellowString(strings.Repeat("|", vmemBarsRes)) +
					color.GreenString(strings.Repeat("|", vmemBarsUsed)) +
					strings.Repeat(" ", vmemBarsUsed+vmemBarsRes)
				if int(barCols) > (vmemBarsUsed + vmemBarsRes) {
					vmemBar = color.YellowString(strings.Repeat("|", vmemBarsRes)) +
						color.GreenString(strings.Repeat("|", vmemBarsUsed)) +
						strings.Repeat(" ", int(barCols)-vmemBarsUsed-vmemBarsRes)
				}

				fmt.Printf("\tRAM:  [%s] %d%% %s/%s\n", ramBar,
					(stat.Info.Resources.MemReserved+stat.MemUsedMin)*100/stat.Info.Resources.MemPhysical,
					types.SizeStr(types.NewInt(stat.Info.Resources.MemReserved+stat.MemUsedMin)),
					types.SizeStr(types.NewInt(stat.Info.Resources.MemPhysical)))

				fmt.Printf("\tVMEM: [%s] %d%% %s/%s\n", vmemBar,
					(stat.Info.Resources.MemReserved+stat.MemUsedMax)*100/vmem,
					types.SizeStr(types.NewInt(stat.Info.Resources.MemReserved+stat.MemUsedMax)),
					types.SizeStr(types.NewInt(vmem)))
			}
			//ramBarsRes := int(stat.Info.Resources.MemReserved * barCols / stat.Info.Resources.MemPhysical)
			//ramBarsUsed := int(stat.MemUsedMin * barCols / stat.Info.Resources.MemPhysical)
			//ramRepeatSpace := int(barCols) - (ramBarsUsed + ramBarsRes)
			//
			//colorFunc := color.YellowString
			//if ramRepeatSpace < 0 {
			//	ramRepeatSpace = 0
			//	colorFunc = color.RedString
			//}
			//
			//ramBar := colorFunc(strings.Repeat("|", ramBarsRes)) +
			//	color.GreenString(strings.Repeat("|", ramBarsUsed)) +
			//	strings.Repeat(" ", ramRepeatSpace)

			//vmem := stat.Info.Resources.MemPhysical + stat.Info.Resources.MemSwap
			//
			//vmemBarsRes := int(stat.Info.Resources.MemReserved * barCols / vmem)
			//vmemBarsUsed := int(stat.MemUsedMax * barCols / vmem)
			//vmemRepeatSpace := int(barCols) - (vmemBarsUsed + vmemBarsRes)
			//
			//colorFunc = color.YellowString
			//if vmemRepeatSpace < 0 {
			//	vmemRepeatSpace = 0
			//	colorFunc = color.RedString
			//}
			//
			//vmemBar := colorFunc(strings.Repeat("|", vmemBarsRes)) +
			//	color.GreenString(strings.Repeat("|", vmemBarsUsed)) +
			//	strings.Repeat(" ", vmemRepeatSpace)

			//fmt.Printf("\tRAM:  [%s] %d%% %s/%s\n", ramBar,
			//	(stat.Info.Resources.MemReserved+stat.MemUsedMin)*100/stat.Info.Resources.MemPhysical,
			//	types.SizeStr(types.NewInt(stat.Info.Resources.MemReserved+stat.MemUsedMin)),
			//	types.SizeStr(types.NewInt(stat.Info.Resources.MemPhysical)))

			//fmt.Printf("\tVMEM: [%s] %d%% %s/%s\n", vmemBar,
			//	(stat.Info.Resources.MemReserved+stat.MemUsedMax)*100/vmem,
			//	types.SizeStr(types.NewInt(stat.Info.Resources.MemReserved+stat.MemUsedMax)),
			//	types.SizeStr(types.NewInt(vmem)))

			for _, gpu := range stat.Info.Resources.GPUs {
				fmt.Printf("\tGPU: %s\n", color.New(gpuCol).Sprintf("%s, %sused", gpu, gpuUse))
			}

			fmt.Printf("\tTypes: [ %s ]\n", stat.TaskTypes)
			if stat.Info.Resources.AddPieceMax == 0 && stat.Info.Resources.PreCommit1Max == 0 && stat.Info.Resources.PreCommit2Max == 0 && stat.Info.Resources.Commit2Max == 0 &&
				stat.Info.Resources.DiskHoldMax == 0 && stat.Info.Resources.APDiskHoldMax == 0 &&
				stat.Info.Resources.ForceP1FromLocalAP == false && stat.Info.Resources.ForceP2FromLocalP1 == false &&
				stat.Info.Resources.ForceC2FromLocalP2 == false && stat.Info.Resources.AllowP2C2Parallel == false {
				fmt.Printf("\tAPMax:%d  P1Max:%d  P2Max:%d  C2Max:%d  BindAP:%t  BindP1:%t  BindP2:%t\n",
					apMaxDefault, p1MaxDefault, p2MaxDefault, c2MaxDefault,
					forceP1FromLocalAPDefault, forceP2FromLocalP1Default, forceC2FromLocalP2Default)
				fmt.Printf("\tTasks: [ %s ] hostname %s [External] \n", stat.Tasks, stat.Info.Hostname)
			} else {
				fmt.Printf("\tAPMax:%d  P1Max:%d  P2Max:%d  C2Max:%d  DiskHoldMax:%d  APDiskHoldMax:%d  BindAP:%t  BindP1:%t  BindP2:%t\n",
					stat.Info.Resources.AddPieceMax, stat.Info.Resources.PreCommit1Max, stat.Info.Resources.PreCommit2Max, stat.Info.Resources.Commit2Max,
					stat.Info.Resources.DiskHoldMax, stat.Info.Resources.APDiskHoldMax, stat.Info.Resources.ForceP1FromLocalAP, stat.Info.Resources.ForceP2FromLocalP1, stat.Info.Resources.ForceC2FromLocalP2)
				fmt.Printf("\tTasks: [ %s ] hostname %s\n", stat.Tasks, stat.Info.Hostname)

			}
			if stat.Info.Resources.IsMiner && endDate != "" {
				fmt.Printf("\tKeys: You have been authorized by FilGuard to %s for %s\n", endDate, minerId)
			}
		}

		return nil
	},
}

var sealingJobsCmd = &cli.Command{
	Name:  "jobs",
	Usage: "list running jobs",
	Flags: []cli.Flag{
		&cli.BoolFlag{
			Name:        "color",
			Usage:       "use color in display output",
			DefaultText: "depends on output being a TTY",
		},
		&cli.BoolFlag{
			Name:  "show-ret-done",
			Usage: "show returned but not consumed calls",
		},
	},
	Action: func(cctx *cli.Context) error {
		if cctx.IsSet("color") {
			color.NoColor = !cctx.Bool("color")
		}

		nodeApi, closer, err := lcli.GetStorageMinerAPI(cctx)
		if err != nil {
			return err
		}
		defer closer()

		ctx := lcli.ReqContext(cctx)

		jobs, err := nodeApi.WorkerJobs(ctx)
		if err != nil {
			return xerrors.Errorf("getting worker jobs: %w", err)
		}

		type line struct {
			storiface.WorkerJob
			wid uuid.UUID
		}

		lines := make([]line, 0)

		for wid, jobs := range jobs {
			for _, job := range jobs {
				lines = append(lines, line{
					WorkerJob: job,
					wid:       wid,
				})
			}
		}

		// oldest first
		sort.Slice(lines, func(i, j int) bool {
			if lines[i].RunWait != lines[j].RunWait {
				return lines[i].RunWait < lines[j].RunWait
			}
			if lines[i].Start.Equal(lines[j].Start) {
				return lines[i].ID.ID.String() < lines[j].ID.ID.String()
			}
			return lines[i].Start.Before(lines[j].Start)
		})

		//workerHostnames := map[uuid.UUID]string{}
		//
		//wst, err := nodeApi.WorkerStats(ctx)
		//if err != nil {
		//	return xerrors.Errorf("getting worker stats: %w", err)
		//}
		//
		//for wid, st := range wst {
		//	workerHostnames[wid] = st.Info.Hostname
		//}

		tw := tabwriter.NewWriter(os.Stdout, 2, 4, 2, ' ', 0)
		_, _ = fmt.Fprintf(tw, "ID\tSector\tWorker\tHostname\tTask\tState\tTime\n")

		for _, l := range lines {
			state := "running"
			switch {
			case l.RunWait > 0:
				state = fmt.Sprintf("assigned(%d)", l.RunWait-1)
			case l.RunWait == storiface.RWRetDone:
				if !cctx.Bool("show-ret-done") {
					continue
				}
				state = "ret-done"
			case l.RunWait == storiface.RWReturned:
				state = "returned"
			case l.RunWait == storiface.RWRetWait:
				state = "ret-wait"
			}
			dur := "n/a"
			if !l.Start.IsZero() {
				dur = time.Now().Sub(l.Start).Truncate(time.Millisecond * 100).String()
			}

			//hostname, ok := workerHostnames[l.wid]
			//if !ok {
			//	hostname = l.Hostname
			//}

			_, _ = fmt.Fprintf(tw, "%s\t%d\t%s\t%s\t%s\t%s\t%s\n",
				hex.EncodeToString(l.ID.ID[:4]),
				l.Sector.Number,
				hex.EncodeToString(l.wid[:4]),
				l.Hostname, //hostname,
				l.Task.Short(),
				state,
				dur)
		}

		return tw.Flush()
	},
}

var sealingSchedDiagCmd = &cli.Command{
	Name:  "sched-diag",
	Usage: "Dump internal scheduler state",
	Flags: []cli.Flag{
		&cli.BoolFlag{
			Name: "force-sched",
		},
	},
	Action: func(cctx *cli.Context) error {
		nodeApi, closer, err := lcli.GetStorageMinerAPI(cctx)
		if err != nil {
			return err
		}
		defer closer()

		ctx := lcli.ReqContext(cctx)

		st, err := nodeApi.SealingSchedDiag(ctx, cctx.Bool("force-sched"))
		if err != nil {
			return err
		}

		j, err := json.MarshalIndent(&st, "", "  ")
		if err != nil {
			return err
		}

		fmt.Println(string(j))

		return nil
	},
}

var sealingAbortCmd = &cli.Command{
	Name:      "abort",
	Usage:     "Abort a running job",
	ArgsUsage: "[callid]",
	Action: func(cctx *cli.Context) error {
		if cctx.Args().Len() != 1 {
			return xerrors.Errorf("expected 1 argument")
		}

		nodeApi, closer, err := lcli.GetStorageMinerAPI(cctx)
		if err != nil {
			return err
		}
		defer closer()

		ctx := lcli.ReqContext(cctx)

		jobs, err := nodeApi.WorkerJobs(ctx)
		if err != nil {
			return xerrors.Errorf("getting worker jobs: %w", err)
		}

		var job *storiface.WorkerJob
	outer:
		for _, workerJobs := range jobs {
			for _, j := range workerJobs {
				if strings.HasPrefix(j.ID.ID.String(), cctx.Args().First()) {
					j := j
					job = &j
					break outer
				}
			}
		}

		if job == nil {
			return xerrors.Errorf("job with specified id prefix not found")
		}

		fmt.Printf("aborting job %s, task %s, sector %d, running on host %s\n", job.ID.String(), job.Task.Short(), job.Sector.Number, job.Hostname)

		return nodeApi.SealingAbort(ctx, job.ID)
	},
}
