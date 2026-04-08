package cmd

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"sync"
	"testing"
	"time"
)

type bucketTestCase struct {
	name        string
	lockEnabled bool
	forceCreate bool
}

var testCases = []bucketTestCase{
	{"baseline", false, false},
	{"lock_only", true, false},
	{"force_only", false, true},
	{"lock_and_force", true, true}, // ключевой кейс
}

func logStats(prefix string, start time.Time) {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	fmt.Printf(
		"%s duration=%v goroutines=%d heap=%dMB GC=%d\n",
		prefix,
		time.Since(start),
		runtime.NumGoroutine(),
		m.HeapAlloc/1024/1024,
		m.NumGC,
	)
}

func runMakeBucketLoop(
	t *testing.T,
	objAPI ObjectLayer,
	caseCfg bucketTestCase,
	workers int,
	iterations int,
) {
	ctx := context.Background()

	var wg sync.WaitGroup
	wg.Add(workers)

	for w := 0; w < workers; w++ {
		go func(id int) {
			defer wg.Done()

			for i := 0; i < iterations; i++ {
				bucket := fmt.Sprintf("poc-%s-%d-%d", caseCfg.name, id, i)

				start := time.Now()

				err := objAPI.MakeBucket(ctx, bucket, MakeBucketOptions{
					LockEnabled: caseCfg.lockEnabled,
					ForceCreate: caseCfg.forceCreate,
				})

				dur := time.Since(start)

				if dur > 20*time.Millisecond {
					fmt.Printf(
						"SLOW case=%s duration=%v err=%v\n",
						caseCfg.name,
						dur,
						err,
					)
				}

				// периодическая телеметрия
				if i%50 == 0 {
					logStats(fmt.Sprintf("STAT case=%s", caseCfg.name), start)
				}
			}
		}(w)
	}

	wg.Wait()
}

func TestMakeBucket_POC_All(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Minute)
	defer cancel()

	objAPI, fsDirs, err := prepareErasure(ctx, 8)
	if err != nil {
		t.Fatal("Unable to initialize 'Erasure' object layer.", err)
	}
	for _, dir := range fsDirs {
		defer os.RemoveAll(dir)
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			fmt.Printf("\n=== RUN CASE: %s ===\n", tc.name)

			start := time.Now()

			runMakeBucketLoop(
				t,
				objAPI,
				tc,
				8,   // можно варьировать
				500, // регулирует длительность
			)

			fmt.Printf("=== DONE %s in %v ===\n", tc.name, time.Since(start))
		})
	}
}
