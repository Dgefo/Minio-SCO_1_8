package cmd

import (
	"encoding/json"
	"testing"
)

// Fuzz_XLMetaV2_LoadAndOps — упрощённый и более стабильный вариант фузз-цели.
func Fuzz_XLMetaV2_LoadAndOps(f *testing.F) {
	// realistic seed: сформируем валидный xlMetaV2 и сериализуем
	{
		var x xlMetaV2
		fi := FileInfo{
			Volume:    "volume",
			Name:      "object",
			VersionID: "seed-version",
			DataDir:   "seed-data",
			ModTime:   UTCNow(),
			Size:      123,
		}
		_ = x.AddVersion(fi)
		if seed, err := x.AppendTo(nil); err == nil && len(seed) > 0 {
			f.Add(seed)
		}
	}

	// пара небольших некорректных/пустых seed'ов
	f.Add([]byte(`{}`))
	f.Add([]byte{0x00, 0x01, 0x02})
	f.Add([]byte(`not-json`))

	f.Fuzz(func(t *testing.T, data []byte) {
		// ограничение размера
		if len(data) > 2<<20 {
			t.Skip()
		}

		// 1) Load
		var x xlMetaV2
		_ = x.Load(data)

		// 2) AppendTo (encode again)
		_, _ = x.AppendTo(nil)

		// 3) Ops like in Benchmarks, но с реалистичным FileInfo
		fi := FileInfo{
			Volume:    "v",
			Name:      "o",
			VersionID: "v-seed",
			DataDir:   "d-seed",
			ModTime:   UTCNow(),
			Size:      1,
		}
		_ = x.AddVersion(fi)
		_ = x.UpdateObjectVersion(fi)
		_, _ = x.DeleteVersion(fi)
		_, _ = x.ToFileInfo("v", "p", fi.VersionID, false, true)
		_, _ = x.ListVersions("v", "p", true)

		// 4) isIndexedMetaV2 path
		buf, _, _ := isIndexedMetaV2(data)
		if buf != nil {
			_, _ = buf.ToFileInfo("v", "p", fi.VersionID, true)
			_, _ = buf.ListVersions("v", "p", true)
		}

		// extra: try treating data as JSON into xlMetaV1 object (optional)
		var maybe interface{}
		_ = json.Unmarshal(data, &maybe)
		_, _ = json.Marshal(maybe)

		// Avoid swallowing panics: do not recover here — let fuzz discover them.
	})
}
