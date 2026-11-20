window.BENCHMARK_DATA = {
  "lastUpdate": 1795216332229,
  "repoUrl": "https://github.com/ashim-kr-saha/shamir_share",
  "entries": {
    "Benchmark": [
      {
        "commit": {
          "author": {
            "email": "32305652+ashim-kr-saha@users.noreply.github.com",
            "name": "Ashim",
            "username": "ashim-kr-saha"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "bfa224d89b82491ef78c1a6253cf30b3aef42fd0",
          "message": "Merge pull request #4 from ashim-kr-saha/copilot/fix-update-benchmark-history\n\nFix benchmark history publishing",
          "timestamp": "2026-11-21T03:28:22+05:30",
          "tree_id": "b110c0428e50128e6c845dc41cf60a581fb30a25",
          "url": "https://github.com/ashim-kr-saha/shamir_share/commit/bfa224d89b82491ef78c1a6253cf30b3aef42fd0"
        },
        "date": 1795212798070,
        "tool": "cargo",
        "benches": [
          {
            "name": "split 1024 bytes",
            "value": 4390459,
            "range": "± 19753",
            "unit": "ns/iter"
          },
          {
            "name": "reconstruct secret",
            "value": 7106,
            "range": "± 219",
            "unit": "ns/iter"
          },
          {
            "name": "HSSS Split Simple/simple_scheme/1024_bytes",
            "value": 353086,
            "range": "± 6630",
            "unit": "ns/iter"
          },
          {
            "name": "HSSS Split Simple/simple_scheme/10240_bytes",
            "value": 3336839,
            "range": "± 25308",
            "unit": "ns/iter"
          },
          {
            "name": "HSSS Split Simple/simple_scheme/102400_bytes",
            "value": 33197754,
            "range": "± 620164",
            "unit": "ns/iter"
          },
          {
            "name": "HSSS Split Complex/complex_scheme/1024_bytes",
            "value": 3933420,
            "range": "± 75399",
            "unit": "ns/iter"
          },
          {
            "name": "HSSS Split Complex/complex_scheme/10240_bytes",
            "value": 37137655,
            "range": "± 181966",
            "unit": "ns/iter"
          },
          {
            "name": "HSSS Split Complex/complex_scheme/102400_bytes",
            "value": 370540960,
            "range": "± 2319993",
            "unit": "ns/iter"
          },
          {
            "name": "HSSS Split Large Secrets/complex_hierarchy_100KB",
            "value": 230281895,
            "range": "± 2432752",
            "unit": "ns/iter"
          },
          {
            "name": "HSSS Reconstruct Simple/simple_scheme/1024_bytes",
            "value": 38247,
            "range": "± 570",
            "unit": "ns/iter"
          },
          {
            "name": "HSSS Reconstruct Simple/simple_scheme/10240_bytes",
            "value": 348147,
            "range": "± 4605",
            "unit": "ns/iter"
          },
          {
            "name": "HSSS Reconstruct Simple/simple_scheme/102400_bytes",
            "value": 3454965,
            "range": "± 52075",
            "unit": "ns/iter"
          },
          {
            "name": "HSSS Reconstruct Complex/complex_scheme/1024_bytes",
            "value": 75571,
            "range": "± 2535",
            "unit": "ns/iter"
          },
          {
            "name": "HSSS Reconstruct Complex/complex_scheme/10240_bytes",
            "value": 686094,
            "range": "± 1895",
            "unit": "ns/iter"
          },
          {
            "name": "HSSS Reconstruct Complex/complex_scheme/102400_bytes",
            "value": 6796790,
            "range": "± 127913",
            "unit": "ns/iter"
          },
          {
            "name": "HSSS Reconstruct Collaboration/president_alone",
            "value": 38245,
            "range": "± 110",
            "unit": "ns/iter"
          },
          {
            "name": "HSSS Reconstruct Collaboration/vp_executive_collaboration",
            "value": 38345,
            "range": "± 689",
            "unit": "ns/iter"
          },
          {
            "name": "HSSS Reconstruct Collaboration/all_levels_together",
            "value": 244126,
            "range": "± 1892",
            "unit": "ns/iter"
          },
          {
            "name": "HSSS vs Shamir Comparison/regular_shamir_1KB",
            "value": 119266,
            "range": "± 2343",
            "unit": "ns/iter"
          },
          {
            "name": "HSSS vs Shamir Comparison/hsss_workflow_1KB",
            "value": 119928,
            "range": "± 1143",
            "unit": "ns/iter"
          },
          {
            "name": "HSSS Scheme Creation/simple_scheme_creation",
            "value": 142,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "HSSS Scheme Creation/complex_scheme_creation",
            "value": 543,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "split/split_1024_bytes",
            "value": 90540,
            "range": "± 1235",
            "unit": "ns/iter"
          },
          {
            "name": "split/split_10240_bytes",
            "value": 851387,
            "range": "± 2140",
            "unit": "ns/iter"
          },
          {
            "name": "split/split_102400_bytes",
            "value": 8477217,
            "range": "± 32539",
            "unit": "ns/iter"
          },
          {
            "name": "split/split_1048576_bytes",
            "value": 91017037,
            "range": "± 603037",
            "unit": "ns/iter"
          },
          {
            "name": "reconstruct/reconstruct_1024_bytes",
            "value": 23344,
            "range": "± 141",
            "unit": "ns/iter"
          },
          {
            "name": "reconstruct/reconstruct_10240_bytes",
            "value": 213285,
            "range": "± 401",
            "unit": "ns/iter"
          },
          {
            "name": "reconstruct/reconstruct_102400_bytes",
            "value": 2119308,
            "range": "± 8986",
            "unit": "ns/iter"
          },
          {
            "name": "reconstruct/reconstruct_1048576_bytes",
            "value": 21728433,
            "range": "± 415195",
            "unit": "ns/iter"
          },
          {
            "name": "full_workflow/workflow_1024_bytes",
            "value": 114386,
            "range": "± 1916",
            "unit": "ns/iter"
          },
          {
            "name": "full_workflow/workflow_10240_bytes",
            "value": 1068795,
            "range": "± 8589",
            "unit": "ns/iter"
          },
          {
            "name": "full_workflow/workflow_102400_bytes",
            "value": 10612332,
            "range": "± 293647",
            "unit": "ns/iter"
          },
          {
            "name": "full_workflow/workflow_1048576_bytes",
            "value": 112920823,
            "range": "± 428352",
            "unit": "ns/iter"
          },
          {
            "name": "refresh_shares/refresh_shares/10_shares",
            "value": 960676,
            "range": "± 3219",
            "unit": "ns/iter"
          },
          {
            "name": "refresh_shares/refresh_shares/50_shares",
            "value": 22406941,
            "range": "± 609558",
            "unit": "ns/iter"
          },
          {
            "name": "refresh_shares/refresh_shares/100_shares",
            "value": 88382257,
            "range": "± 417723",
            "unit": "ns/iter"
          },
          {
            "name": "refresh_shares/refresh_shares/200_shares",
            "value": 352719768,
            "range": "± 1837215",
            "unit": "ns/iter"
          },
          {
            "name": "refresh_shares_data_size/refresh_shares_data_size/256_bytes",
            "value": 7122330,
            "range": "± 189601",
            "unit": "ns/iter"
          },
          {
            "name": "refresh_shares_data_size/refresh_shares_data_size/1024_bytes",
            "value": 22417706,
            "range": "± 81839",
            "unit": "ns/iter"
          },
          {
            "name": "refresh_shares_data_size/refresh_shares_data_size/4096_bytes",
            "value": 83384255,
            "range": "± 1714083",
            "unit": "ns/iter"
          },
          {
            "name": "refresh_shares_data_size/refresh_shares_data_size/16384_bytes",
            "value": 327490894,
            "range": "± 3547916",
            "unit": "ns/iter"
          },
          {
            "name": "refresh_vs_split/split_100_shares",
            "value": 88465709,
            "range": "± 1774784",
            "unit": "ns/iter"
          },
          {
            "name": "refresh_vs_split/refresh_100_shares",
            "value": 88487144,
            "range": "± 288654",
            "unit": "ns/iter"
          },
          {
            "name": "split_stream/split_stream/1024_bytes",
            "value": 1242548,
            "range": "± 22259",
            "unit": "ns/iter"
          },
          {
            "name": "split_stream/split_stream/10240_bytes",
            "value": 1934432,
            "range": "± 47136",
            "unit": "ns/iter"
          },
          {
            "name": "split_stream/split_stream/102400_bytes",
            "value": 9786502,
            "range": "± 244443",
            "unit": "ns/iter"
          },
          {
            "name": "split_stream/split_stream/1048576_bytes",
            "value": 93725080,
            "range": "± 2288489",
            "unit": "ns/iter"
          },
          {
            "name": "reconstruct_stream/reconstruct_stream/1024_bytes",
            "value": 94895,
            "range": "± 353",
            "unit": "ns/iter"
          },
          {
            "name": "reconstruct_stream/reconstruct_stream/10240_bytes",
            "value": 306465,
            "range": "± 2049",
            "unit": "ns/iter"
          },
          {
            "name": "reconstruct_stream/reconstruct_stream/102400_bytes",
            "value": 2425117,
            "range": "± 23887",
            "unit": "ns/iter"
          },
          {
            "name": "reconstruct_stream/reconstruct_stream/1048576_bytes",
            "value": 24964303,
            "range": "± 92140",
            "unit": "ns/iter"
          },
          {
            "name": "Streaming vs In-Memory Comparison/in_memory_workflow_100KB",
            "value": 10973902,
            "range": "± 69077",
            "unit": "ns/iter"
          },
          {
            "name": "Streaming vs In-Memory Comparison/streaming_workflow_100KB",
            "value": 11038316,
            "range": "± 49208",
            "unit": "ns/iter"
          },
          {
            "name": "split_stream_chunk_sizes/chunk_size/1024_bytes",
            "value": 11172863,
            "range": "± 233331",
            "unit": "ns/iter"
          },
          {
            "name": "split_stream_chunk_sizes/chunk_size/4096_bytes",
            "value": 8814252,
            "range": "± 95439",
            "unit": "ns/iter"
          },
          {
            "name": "split_stream_chunk_sizes/chunk_size/16384_bytes",
            "value": 8248873,
            "range": "± 71820",
            "unit": "ns/iter"
          },
          {
            "name": "split_stream_chunk_sizes/chunk_size/65536_bytes",
            "value": 8132154,
            "range": "± 35608",
            "unit": "ns/iter"
          },
          {
            "name": "streaming_integrity_check/with_integrity_check",
            "value": 11026628,
            "range": "± 308431",
            "unit": "ns/iter"
          },
          {
            "name": "streaming_integrity_check/without_integrity_check",
            "value": 10878520,
            "range": "± 84208",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "ashimsaha2311@gmail.com",
            "name": "Ashim",
            "username": "ashim-kr-saha"
          },
          "committer": {
            "email": "ashimsaha2311@gmail.com",
            "name": "Ashim",
            "username": "ashim-kr-saha"
          },
          "distinct": true,
          "id": "eb84b46f19c12dbe378396d8fe032efa9b143fd4",
          "message": "feat: add context7.json configuration file",
          "timestamp": "2026-11-21T04:25:50+05:30",
          "tree_id": "6d0799945fc091a240c0f52a8ad35b810afd8d4d",
          "url": "https://github.com/ashim-kr-saha/shamir_share/commit/eb84b46f19c12dbe378396d8fe032efa9b143fd4"
        },
        "date": 1795216331867,
        "tool": "cargo",
        "benches": [
          {
            "name": "split 1024 bytes",
            "value": 7133113,
            "range": "± 30040",
            "unit": "ns/iter"
          },
          {
            "name": "reconstruct secret",
            "value": 10019,
            "range": "± 16",
            "unit": "ns/iter"
          },
          {
            "name": "HSSS Split Simple/simple_scheme/1024_bytes",
            "value": 576375,
            "range": "± 11249",
            "unit": "ns/iter"
          },
          {
            "name": "HSSS Split Simple/simple_scheme/10240_bytes",
            "value": 5443954,
            "range": "± 39267",
            "unit": "ns/iter"
          },
          {
            "name": "HSSS Split Simple/simple_scheme/102400_bytes",
            "value": 54123956,
            "range": "± 772855",
            "unit": "ns/iter"
          },
          {
            "name": "HSSS Split Complex/complex_scheme/1024_bytes",
            "value": 6576838,
            "range": "± 10725",
            "unit": "ns/iter"
          },
          {
            "name": "HSSS Split Complex/complex_scheme/10240_bytes",
            "value": 62231052,
            "range": "± 68344",
            "unit": "ns/iter"
          },
          {
            "name": "HSSS Split Complex/complex_scheme/102400_bytes",
            "value": 621728195,
            "range": "± 876492",
            "unit": "ns/iter"
          },
          {
            "name": "HSSS Split Large Secrets/complex_hierarchy_100KB",
            "value": 385990270,
            "range": "± 1498888",
            "unit": "ns/iter"
          },
          {
            "name": "HSSS Reconstruct Simple/simple_scheme/1024_bytes",
            "value": 54823,
            "range": "± 97",
            "unit": "ns/iter"
          },
          {
            "name": "HSSS Reconstruct Simple/simple_scheme/10240_bytes",
            "value": 498901,
            "range": "± 477",
            "unit": "ns/iter"
          },
          {
            "name": "HSSS Reconstruct Simple/simple_scheme/102400_bytes",
            "value": 4932555,
            "range": "± 11734",
            "unit": "ns/iter"
          },
          {
            "name": "HSSS Reconstruct Complex/complex_scheme/1024_bytes",
            "value": 110247,
            "range": "± 1681",
            "unit": "ns/iter"
          },
          {
            "name": "HSSS Reconstruct Complex/complex_scheme/10240_bytes",
            "value": 989378,
            "range": "± 4262",
            "unit": "ns/iter"
          },
          {
            "name": "HSSS Reconstruct Complex/complex_scheme/102400_bytes",
            "value": 9781917,
            "range": "± 32160",
            "unit": "ns/iter"
          },
          {
            "name": "HSSS Reconstruct Collaboration/president_alone",
            "value": 54900,
            "range": "± 121",
            "unit": "ns/iter"
          },
          {
            "name": "HSSS Reconstruct Collaboration/vp_executive_collaboration",
            "value": 54827,
            "range": "± 157",
            "unit": "ns/iter"
          },
          {
            "name": "HSSS Reconstruct Collaboration/all_levels_together",
            "value": 353680,
            "range": "± 4098",
            "unit": "ns/iter"
          },
          {
            "name": "HSSS vs Shamir Comparison/regular_shamir_1KB",
            "value": 176736,
            "range": "± 686",
            "unit": "ns/iter"
          },
          {
            "name": "HSSS vs Shamir Comparison/hsss_workflow_1KB",
            "value": 177838,
            "range": "± 318",
            "unit": "ns/iter"
          },
          {
            "name": "HSSS Scheme Creation/simple_scheme_creation",
            "value": 128,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "HSSS Scheme Creation/complex_scheme_creation",
            "value": 449,
            "range": "± 8",
            "unit": "ns/iter"
          },
          {
            "name": "split/split_1024_bytes",
            "value": 143478,
            "range": "± 1908",
            "unit": "ns/iter"
          },
          {
            "name": "split/split_10240_bytes",
            "value": 1354170,
            "range": "± 2162",
            "unit": "ns/iter"
          },
          {
            "name": "split/split_102400_bytes",
            "value": 13461124,
            "range": "± 18286",
            "unit": "ns/iter"
          },
          {
            "name": "split/split_1048576_bytes",
            "value": 141603278,
            "range": "± 326678",
            "unit": "ns/iter"
          },
          {
            "name": "reconstruct/reconstruct_1024_bytes",
            "value": 33160,
            "range": "± 87",
            "unit": "ns/iter"
          },
          {
            "name": "reconstruct/reconstruct_10240_bytes",
            "value": 302613,
            "range": "± 426",
            "unit": "ns/iter"
          },
          {
            "name": "reconstruct/reconstruct_102400_bytes",
            "value": 2993814,
            "range": "± 17805",
            "unit": "ns/iter"
          },
          {
            "name": "reconstruct/reconstruct_1048576_bytes",
            "value": 30625250,
            "range": "± 59664",
            "unit": "ns/iter"
          },
          {
            "name": "full_workflow/workflow_1024_bytes",
            "value": 176787,
            "range": "± 515",
            "unit": "ns/iter"
          },
          {
            "name": "full_workflow/workflow_10240_bytes",
            "value": 1657290,
            "range": "± 5305",
            "unit": "ns/iter"
          },
          {
            "name": "full_workflow/workflow_102400_bytes",
            "value": 16462608,
            "range": "± 201055",
            "unit": "ns/iter"
          },
          {
            "name": "full_workflow/workflow_1048576_bytes",
            "value": 172433131,
            "range": "± 265186",
            "unit": "ns/iter"
          },
          {
            "name": "refresh_shares/refresh_shares/10_shares",
            "value": 1498752,
            "range": "± 3783",
            "unit": "ns/iter"
          },
          {
            "name": "refresh_shares/refresh_shares/50_shares",
            "value": 36531034,
            "range": "± 21471",
            "unit": "ns/iter"
          },
          {
            "name": "refresh_shares/refresh_shares/100_shares",
            "value": 145565674,
            "range": "± 495748",
            "unit": "ns/iter"
          },
          {
            "name": "refresh_shares/refresh_shares/200_shares",
            "value": 581463130,
            "range": "± 976325",
            "unit": "ns/iter"
          },
          {
            "name": "refresh_shares_data_size/refresh_shares_data_size/256_bytes",
            "value": 11121069,
            "range": "± 18845",
            "unit": "ns/iter"
          },
          {
            "name": "refresh_shares_data_size/refresh_shares_data_size/1024_bytes",
            "value": 36529413,
            "range": "± 369126",
            "unit": "ns/iter"
          },
          {
            "name": "refresh_shares_data_size/refresh_shares_data_size/4096_bytes",
            "value": 138194358,
            "range": "± 397873",
            "unit": "ns/iter"
          },
          {
            "name": "refresh_shares_data_size/refresh_shares_data_size/16384_bytes",
            "value": 544696178,
            "range": "± 775863",
            "unit": "ns/iter"
          },
          {
            "name": "refresh_vs_split/split_100_shares",
            "value": 145176123,
            "range": "± 795468",
            "unit": "ns/iter"
          },
          {
            "name": "refresh_vs_split/refresh_100_shares",
            "value": 145569164,
            "range": "± 542504",
            "unit": "ns/iter"
          },
          {
            "name": "split_stream/split_stream/1024_bytes",
            "value": 1269057,
            "range": "± 11032",
            "unit": "ns/iter"
          },
          {
            "name": "split_stream/split_stream/10240_bytes",
            "value": 2477250,
            "range": "± 26372",
            "unit": "ns/iter"
          },
          {
            "name": "split_stream/split_stream/102400_bytes",
            "value": 15528221,
            "range": "± 46982",
            "unit": "ns/iter"
          },
          {
            "name": "split_stream/split_stream/1048576_bytes",
            "value": 151781197,
            "range": "± 475300",
            "unit": "ns/iter"
          },
          {
            "name": "reconstruct_stream/reconstruct_stream/1024_bytes",
            "value": 83979,
            "range": "± 290",
            "unit": "ns/iter"
          },
          {
            "name": "reconstruct_stream/reconstruct_stream/10240_bytes",
            "value": 379410,
            "range": "± 446",
            "unit": "ns/iter"
          },
          {
            "name": "reconstruct_stream/reconstruct_stream/102400_bytes",
            "value": 3325346,
            "range": "± 4101",
            "unit": "ns/iter"
          },
          {
            "name": "reconstruct_stream/reconstruct_stream/1048576_bytes",
            "value": 33729758,
            "range": "± 22460",
            "unit": "ns/iter"
          },
          {
            "name": "Streaming vs In-Memory Comparison/in_memory_workflow_100KB",
            "value": 16452346,
            "range": "± 15857",
            "unit": "ns/iter"
          },
          {
            "name": "Streaming vs In-Memory Comparison/streaming_workflow_100KB",
            "value": 17750789,
            "range": "± 57927",
            "unit": "ns/iter"
          },
          {
            "name": "split_stream_chunk_sizes/chunk_size/1024_bytes",
            "value": 16782484,
            "range": "± 126498",
            "unit": "ns/iter"
          },
          {
            "name": "split_stream_chunk_sizes/chunk_size/4096_bytes",
            "value": 14725086,
            "range": "± 30315",
            "unit": "ns/iter"
          },
          {
            "name": "split_stream_chunk_sizes/chunk_size/16384_bytes",
            "value": 14240113,
            "range": "± 32744",
            "unit": "ns/iter"
          },
          {
            "name": "split_stream_chunk_sizes/chunk_size/65536_bytes",
            "value": 14153315,
            "range": "± 32742",
            "unit": "ns/iter"
          },
          {
            "name": "streaming_integrity_check/with_integrity_check",
            "value": 17747961,
            "range": "± 60766",
            "unit": "ns/iter"
          },
          {
            "name": "streaming_integrity_check/without_integrity_check",
            "value": 17649960,
            "range": "± 51171",
            "unit": "ns/iter"
          }
        ]
      }
    ]
  }
}