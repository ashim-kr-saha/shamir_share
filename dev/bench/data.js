window.BENCHMARK_DATA = {
  "lastUpdate": 1795212798422,
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
      }
    ]
  }
}