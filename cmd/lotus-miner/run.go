package main

import (
	"fmt"
	_ "net/http/pprof"
	"os"

	"encoding/json"
	"github.com/filecoin-project/lotus/extern/sector-storage/stores"
	"io/ioutil"
	"path/filepath"
	scServer "github.com/liusdpc/my-sector-counter/server"

	"github.com/filecoin-project/lotus/api/v1api"

	"github.com/filecoin-project/lotus/api/v0api"

	"github.com/multiformats/go-multiaddr"
	"github.com/urfave/cli/v2"
	"go.opencensus.io/stats"
	"go.opencensus.io/stats/view"
	"go.opencensus.io/tag"
	"golang.org/x/xerrors"

	"github.com/filecoin-project/lotus/api"
	"github.com/filecoin-project/lotus/build"
	lcli "github.com/filecoin-project/lotus/cli"
	"github.com/filecoin-project/lotus/lib/ulimit"
	"github.com/filecoin-project/lotus/metrics"
	"github.com/filecoin-project/lotus/node"
	"github.com/filecoin-project/lotus/node/config"
	"github.com/filecoin-project/lotus/node/modules/dtypes"
	"github.com/filecoin-project/lotus/node/repo"
)

var runCmd = &cli.Command{
	Name:  "run",
	Usage: "Start a lotus miner process",
	Flags: []cli.Flag{
		&cli.BoolFlag{
			Name:  "window-post",
			Usage: "enable window PoSt",
			Value: true,
		},
		&cli.BoolFlag{
			Name:  "winning-post",
			Usage: "enable winning PoSt",
			Value: true,
		},
		&cli.BoolFlag{
			Name:  "p2p",
			Usage: "enable P2P",
			Value: true,
		},
		&cli.StringFlag{
			Name:  "sctype",
			Usage: "sector counter type(alloce,get)",
			Value: "",
		},
		&cli.StringFlag{
			Name:  "sclisten",
			Usage: "host address and port the sector counter will listen on",
			Value: "",
		},
		&cli.StringFlag{
			Name:  "miner-api",
			Usage: "2345",
		},
		&cli.BoolFlag{
			Name:  "enable-gpu-proving",
			Usage: "enable use of GPU for mining operations",
			Value: true,
		},
		&cli.BoolFlag{
			Name:  "nosync",
			Usage: "don't check full-node sync status",
		},
		&cli.BoolFlag{
			Name:  "manage-fdlimit",
			Usage: "manage open file limit",
			Value: true,
		},
	},
	Action: func(cctx *cli.Context) error {
		if cctx.Bool("window-post") {
			os.Setenv("LOTUS_WINDOW_POST", "true")
		} else {
			os.Unsetenv("LOTUS_WINDOW_POST")
		}

		if cctx.Bool("winning-post") {
			os.Setenv("LOTUS_WINNING_POST", "true")
		} else {
			os.Unsetenv("LOTUS_WINNING_POST")
		}

		scType := cctx.String("sctype")
		if scType == "alloce" || scType == "get" {
			os.Setenv("SC_TYPE", scType)

			scListen := cctx.String("sclisten")
			if scListen == "" {
				log.Errorf("sclisten must be set")
				return nil
			}
			os.Setenv("SC_LISTEN", scListen)

			if scType == "alloce" {
				scFilePath := filepath.Join(cctx.String(FlagMinerRepo), "sectorid")
				go scServer.Run(scFilePath)
			}
		} else {
			os.Unsetenv("SC_TYPE")
		}

		if !cctx.Bool("enable-gpu-proving") {
			err := os.Setenv("BELLMAN_NO_GPU", "true")
			if err != nil {
				return err
			}
		}

		ctx, _ := tag.New(lcli.DaemonContext(cctx),
			tag.Insert(metrics.Version, build.BuildVersion),
			tag.Insert(metrics.Commit, build.CurrentCommit),
			tag.Insert(metrics.NodeType, "miner"),
		)
		// Register all metric views
		if err := view.Register(
			metrics.MinerNodeViews...,
		); err != nil {
			log.Fatalf("Cannot register the view: %v", err)
		}
		// Set the metric to one so it is published to the exporter
		stats.Record(ctx, metrics.LotusInfo.M(1))

		if err := checkV1ApiSupport(ctx, cctx); err != nil {
			return err
		}

		nodeApi, ncloser, err := lcli.GetFullNodeAPIV1(cctx)
		if err != nil {
			return xerrors.Errorf("getting full node api: %w", err)
		}
		defer ncloser()

		v, err := nodeApi.Version(ctx)
		if err != nil {
			return err
		}

		if cctx.Bool("manage-fdlimit") {
			if _, _, err := ulimit.ManageFdLimit(); err != nil {
				log.Errorf("setting file descriptor limit: %s", err)
			}
		}

		if v.APIVersion != api.FullAPIVersion1 {
			return xerrors.Errorf("lotus-daemon API version doesn't match: expected: %s", api.APIVersion{APIVersion: api.FullAPIVersion1})
		}

		log.Info("Checking full node sync status")

		if !cctx.Bool("nosync") {
			if err := lcli.SyncWait(ctx, &v0api.WrapperV1Full{FullNode: nodeApi}, false); err != nil {
				return xerrors.Errorf("sync wait: %w", err)
			}
		}

		minerRepoPath := cctx.String(FlagMinerRepo)
		r, err := repo.NewFS(minerRepoPath)
		if err != nil {
			return err
		}

		ok, err := r.Exists()
		if err != nil {
			return err
		}
		if !ok {
			return xerrors.Errorf("repo at '%s' is not initialized, run 'lotus-miner init' to set it up", minerRepoPath)
		}

		hostname, err := os.Hostname()
		if err != nil {
			hostname = ""
		}
		fileDst := filepath.Join(minerRepoPath, "myscheduler.json")
		_, errorFile := os.Stat(fileDst)
		if os.IsNotExist(errorFile) {
			//persisting myScheduler metadata start//
			b, err := json.MarshalIndent(&stores.MySchedulerMeta{
				WorkerName:         hostname,
				AddPieceMax:        uint64(0),
				PreCommit1Max:      uint64(0),
				PreCommit2Max:      uint64(0),
				Commit2Max:         uint64(0),
				DiskHoldMax:        uint64(0),
				APDiskHoldMax:      uint64(0),
				ForceP1FromLocalAP: true,
				ForceP2FromLocalP1: true,
				ForceC2FromLocalP2: false,
				IsPlanOffline:      false,
				AllowP2C2Parallel:  false,
				AutoPledgeDiff:     uint64(0),
			}, "", "  ")
			if err != nil {
				//return xerrors.Errorf("marshaling myScheduler config: %w", err)
				log.Error("marshaling myScheduler config:", err)
			}
			if err := ioutil.WriteFile(filepath.Join(minerRepoPath, "myscheduler.json"), b, 0644); err != nil {
				//return xerrors.Errorf("persisting myScheduler metadata (%s): %w", filepath.Join(minerRepoPath, "myscheduler.json"), err)
				log.Error("persisting myScheduler metadata:", err)
			}
			//persisting myScheduler metadata end//
		}

		fileDst = filepath.Join(minerRepoPath, "externalWorker.json")
		_, errorFile = os.Stat(fileDst)
		if os.IsNotExist(errorFile) {
			//persisting TestSchedulerMeta metadata start//
			b, err := json.MarshalIndent(&stores.TestSchedulerMeta{
				AddPieceMax:        uint64(1),
				PreCommit1Max:      uint64(1),
				PreCommit2Max:      uint64(1),
				Commit2Max:         uint64(1),
				ForceP1FromLocalAP: true,
				ForceP2FromLocalP1: true,
				ForceC2FromLocalP2: false,
				AllowP2C2Parallel:  true,
				FiLGuardKey:        "",
				AllowDelay:         uint64(3),
			}, "", "  ")
			if err != nil {
				//return xerrors.Errorf("marshaling TestSchedulerMeta config: %w", err)
				log.Error("marshaling externalWorker config:", err)
			}
			if err := ioutil.WriteFile(filepath.Join(minerRepoPath, "externalWorker.json"), b, 0644); err != nil {
				//return xerrors.Errorf("persisting testOpenSource metadata (%s): %w", filepath.Join(minerRepoPath, "externalWorker.json"), err)
				log.Error("persisting externalWorker metadata:", err)
			}
			//persisting TestSchedulerMeta metadata end//
		}

		lr, err := r.Lock(repo.StorageMiner)
		if err != nil {
			return err
		}
		c, err := lr.Config()
		if err != nil {
			return err
		}
		cfg, ok := c.(*config.StorageMiner)
		if !ok {
			return xerrors.Errorf("invalid config for repo, got: %T", c)
		}

		bootstrapLibP2P := cfg.Subsystems.EnableMarkets

		err = lr.Close()
		if err != nil {
			return err
		}

		shutdownChan := make(chan struct{})

		var minerapi api.StorageMiner
		stop, err := node.New(ctx,
			node.StorageMiner(&minerapi, cfg.Subsystems),
			node.Override(new(dtypes.ShutdownChan), shutdownChan),
			node.Base(),
			node.Repo(r),

			node.ApplyIf(func(s *node.Settings) bool { return cctx.IsSet("miner-api") },
				node.Override(new(dtypes.APIEndpoint), func() (dtypes.APIEndpoint, error) {
					return multiaddr.NewMultiaddr("/ip4/127.0.0.1/tcp/" + cctx.String("miner-api"))
				})),
			node.Override(new(v1api.FullNode), nodeApi),
		)
		if err != nil {
			return xerrors.Errorf("creating node: %w", err)
		}

		endpoint, err := r.APIEndpoint()
		if err != nil {
			return xerrors.Errorf("getting API endpoint: %w", err)
		}

		if bootstrapLibP2P || cctx.Bool("p2p") {
			log.Infof("Bootstrapping libp2p network with full node")

			// Bootstrap with full node
			remoteAddrs, err := nodeApi.NetAddrsListen(ctx)
			if err != nil {
				return xerrors.Errorf("getting full node libp2p address: %w", err)
			}

			if err := minerapi.NetConnect(ctx, remoteAddrs); err != nil {
				return xerrors.Errorf("connecting to full node (libp2p): %w", err)
			}
		} else {
			log.Warn("Thie miner will be disabled p2p")
		}

		log.Infof("Remote version %s", v)

		// Instantiate the miner node handler.
		handler, err := node.MinerHandler(minerapi, true)
		if err != nil {
			return xerrors.Errorf("failed to instantiate rpc handler: %w", err)
		}

		// Serve the RPC.
		rpcStopper, err := node.ServeRPC(handler, "lotus-miner", endpoint)
		if err != nil {
			return fmt.Errorf("failed to start json-rpc endpoint: %s", err)
		}

		// Monitor for shutdown.
		finishCh := node.MonitorShutdown(shutdownChan,
			node.ShutdownHandler{Component: "rpc server", StopFunc: rpcStopper},
			node.ShutdownHandler{Component: "miner", StopFunc: stop},
		)

		<-finishCh
		return nil
	},
}
