package cmd

import (
	"testing"
	"time"
)

func makeValidXLMetaV2Seed(tb testing.TB) []byte {
	tb.Helper()

	var x xlMetaV2
	fi := FileInfo{
		Volume:  "volume",
		Name:    "object",
		ModTime: time.Now().UTC(),
		Erasure: ErasureInfo{DataBlocks: 1, ParityBlocks: 0, BlockSize: 1},
	}
	if err := x.AddVersion(fi); err != nil {
		tb.Fatalf("AddVersion of valid seed failed: %v", err)
	}
	seed, err := x.AppendTo(nil)
	if err != nil {
		tb.Fatalf("AppendTo of valid seed failed: %v", err)
	}
	return seed
}

func runXLMetaV2Fuzz(t *testing.T, data []byte) {
	t.Helper()

	if len(data) == 0 || len(data) > 2<<20 {
		t.Skip()
	}

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("panic: %v", r)
		}
	}()

	var x xlMetaV2
	if err := x.Load(data); err != nil {
		return
	}

	encoded, err := x.AppendTo(nil)
	if err != nil {
		t.Fatalf("AppendTo failed after successful Load: %v", err)
	}

	var y xlMetaV2
	if err := y.Load(encoded); err != nil {
		t.Fatalf("roundtrip Load failed: %v", err)
	}
	if _, err := y.AppendTo(nil); err != nil {
		t.Fatalf("AppendTo failed after roundtrip Load: %v", err)
	}

	var fi FileInfo
	if err := y.AddVersion(fi); err != nil {
		t.Fatalf("AddVersion returned error: %v", err)
	}
	_ = y.UpdateObjectVersion(fi)
	_, _ = y.DeleteVersion(fi)
	_, _ = y.ToFileInfo("v", "p", "", false, true)
	_, _ = y.ListVersions("v", "p", true)

	if buf, _, _ := isIndexedMetaV2(data); buf != nil {
		_, _ = buf.ToFileInfo("v", "p", "", true)
		_, _ = buf.ListVersions("v", "p", true)
	}
}

func Fuzz_XLMetaV2_LoadAndOps(f *testing.F) {
	f.Add(makeValidXLMetaV2Seed(f))
	f.Add([]byte(`{}`))
	f.Add([]byte{0x00, 0x01, 0x02})
	f.Add([]byte(`not-json`))
	f.Add([]byte{0xDE, 0xAD, 0xBE, 0xEF})

	f.Fuzz(func(t *testing.T, data []byte) {
		runXLMetaV2Fuzz(t, data)
	})
}
