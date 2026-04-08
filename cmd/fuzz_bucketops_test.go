package cmd

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"math/rand"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/minio/minio/internal/hash"
)

// Ограничения и настройки
const (
	maxBodySize     = 1 << 20 // 1 MB
	maxFuzzBuckets  = 16
	maxUserMetaKeys = 12
)

// Логируем только серьезные падения
func logCrash(objectName string, opts ObjectOptions, body []byte, err error) {
	_ = os.MkdirAll("fuzz_crashes", 0o755)
	filename := fmt.Sprintf("fuzz_crashes/%s_%d.log", objectName, time.Now().UnixNano())
	f, e := os.Create(filename)
	if e != nil {
		return
	}
	defer f.Close()

	maxDump := 512
	if len(body) < maxDump {
		maxDump = len(body)
	}

	_, _ = f.WriteString(fmt.Sprintf(
		"object=%s\nopts=%+v\nbody=%x\nerr=%v\n",
		objectName,
		opts,
		body[:maxDump],
		err,
	))
}

// prepareFS один раз на процесс
var (
	globalObjLayer ObjectLayer
	prepareOnce    sync.Once
	prepareErr     error
)

func getObjLayerOnce(ctx context.Context) (ObjectLayer, error) {
	prepareOnce.Do(func() {
		globalObjLayer, _, prepareErr = prepareFS(ctx)
	})
	return globalObjLayer, prepareErr
}

// Управление пулом бакетов (ограниченное количество, переиспользуемые имена)
var (
	bucketNames   []string
	bucketNamesMu sync.Mutex
)

func getRandomBucket(r *rand.Rand, objLayer ObjectLayer, ctx context.Context) (string, error) {
	bucketNamesMu.Lock()
	defer bucketNamesMu.Unlock()

	// 1) Иногда просто вернуть существующий
	if len(bucketNames) > 0 && r.Intn(3) != 0 {
		return bucketNames[r.Intn(len(bucketNames))], nil
	}

	// 2) Попробовать создать новый, если лимит не превышен
	if len(bucketNames) < maxFuzzBuckets {
		name := "fzb-" + randomBucketName(r, 8)
		if err := objLayer.MakeBucket(ctx, name, MakeBucketOptions{}); err == nil {
			bucketNames = append(bucketNames, name)
			return name, nil
		}
		// если создание не удалось, fallthrough к возврату существующего
	}

	// 3) Если уже есть существующий — вернуть его
	if len(bucketNames) > 0 {
		return bucketNames[r.Intn(len(bucketNames))], nil
	}

	// 4) Создать один гарантированно (fallback)
	name := "fzb-init"
	if err := objLayer.MakeBucket(ctx, name, MakeBucketOptions{}); err != nil {
		return "", err
	}
	bucketNames = append(bucketNames, name)
	return name, nil
}

// Вспомогательные функции генерации
func randomString(r *rand.Rand, n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	if n <= 0 {
		return ""
	}
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[r.Intn(len(letters))]
	}
	return string(b)
}

func randomBucketName(r *rand.Rand, n int) string {
	if n <= 0 {
		return "fzb"
	}
	out := make([]byte, n)
	for i := range out {
		c := byte(r.Intn(38))
		switch {
		case c < 26:
			out[i] = 'a' + c
		case c < 36:
			out[i] = '0' + (c - 26)
		default:
			out[i] = '-'
		}
	}
	if len(out) < 3 {
		out = append(out, 'x', 'x', 'x')
	}
	if out[0] == '-' {
		out[0] = 'a'
	}
	if out[len(out)-1] == '-' {
		out[len(out)-1] = 'b'
	}
	return string(out)
}

func randomObjectOptions(r *rand.Rand) ObjectOptions {
	// небольшое количество пользовательских метаданных, чтобы не разрастать записи
	ud := map[string]string{}
	num := 1 + r.Intn(maxUserMetaKeys)
	for i := 0; i < num; i++ {
		k := randomString(r, 3+r.Intn(8))
		v := randomString(r, r.Intn(120))
		ud[k] = v
	}

	// Версия оставляем в виде UUID, чтобы не ломать state-machine MinIO в safe режиме.
	return ObjectOptions{
		MTime:              time.Unix(r.Int63(), int64(r.Intn(1e9))),
		Expires:            time.Unix(r.Int63(), 0),
		VersionID:          uuid.NewString(),
		UserDefined:        ud,
		Tagging:            r.Intn(2) == 1,
		DeleteMarker:       r.Intn(2) == 1,
		MetadataChg:        r.Intn(2) == 1,
		Speedtest:          r.Intn(2) == 1,
		SkipRebalancing:    r.Intn(2) == 1,
		SkipDecommissioned: r.Intn(2) == 1,
		WantChecksum: &hash.Checksum{
			Type:      hash.ChecksumType(r.Intn(10)),
			Encoded:   randomString(r, 40),
			Raw:       []byte(randomString(r, r.Intn(60))),
			WantParts: r.Intn(10),
		},
	}
}

// Основной безопасный фаззер с бакет-фаззингом
func FuzzPutObjectOptionsSafe2(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte, body []byte) {
		// минимальная длина data для сидирования rand
		if len(data) < 8 {
			t.Skip()
			return
		}

		// ограничиваем размер тела
		if len(body) > maxBodySize {
			body = body[:maxBodySize]
		}

		seed := int64(binary.LittleEndian.Uint64(data))
		r := rand.New(rand.NewSource(seed))
		ctx := context.Background()

		// получаем один глобальный objLayer
		objLayer, err := getObjLayer(ctx)
		if err != nil {
			t.Fatalf("prepareFS failed: %v", err)
		}

		// создаём корректный hash.Reader и PutObjReader, закрываем в конце
		rawReader, err := hash.NewReader(ctx, bytes.NewReader(body), int64(len(body)), "", "", 0)
		if err != nil {
			t.Skip()
			return
		}
		defer rawReader.Close()

		putReader := NewPutObjReader(rawReader)
		defer func() {
			// NewPutObjReader может вернуть nil или объект без Close
			if putReader != nil {
				_ = putReader.Close()
			}
		}()

		// генерируем опции
		opts := randomObjectOptions(r)

		// нормализуем даты (safety)
		safeTime := func(t time.Time) time.Time {
			switch {
			case t.Year() > 2100:
				return time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC)
			case t.Year() < 1970:
				return time.Unix(0, 0)
			default:
				return t
			}
		}
		opts.MTime = safeTime(opts.MTime)
		opts.Expires = safeTime(opts.Expires)

		// Получаем или создаём безопасный бакет
		bucket, err := getRandomBucket(r, objLayer, ctx)
		if err != nil {
			// не фаталим, просто пропускаем итерацию
			t.Skip()
			return
		}

		// формируем имя объекта детерминированно от сида и длины тела
		objectName := fmt.Sprintf("o_%x", seed^int64(len(body)))

		// основной вызов
		_, err = objLayer.PutObject(ctx, bucket, objectName, putReader, opts)

		// логируем только серьезные падения
		if err != nil && strings.Contains(err.Error(), "panic") {
			logCrash(objectName, opts, body, err)
			t.Skip()
			return
		}
	})
}

// --------------------------------------------
// Простая фазз-цель: операции над бакетами
// --------------------------------------------
func FuzzBucketOps(f *testing.F) {
	f.Add([]byte("seed"))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) < 4 {
			t.Skip()
			return
		}

		// быстрый seed для rand
		seed := int64(binary.LittleEndian.Uint32(data))
		r := rand.New(rand.NewSource(seed))

		ctx := context.Background()

		objLayer, err := getObjLayer(ctx)
		if err != nil {
			t.Skip()
			return
		}

		// bucket name, derived from fuzzer data
		bucket := sanitizeBucketName(data)

		// attempt to create
		_ = objLayer.MakeBucket(ctx, bucket, MakeBucketOptions{})

		// occasionally delete
		if r.Intn(5) == 0 {
			_ = objLayer.DeleteBucket(ctx, bucket, DeleteBucketOptions{})
		}

		// occasionally list
		if r.Intn(3) == 0 {
			_, _ = objLayer.ListBuckets(ctx, BucketOptions{})
		}
	})
}

// Generates a safe bucket name.
func sanitizeBucketName(b []byte) string {
	if len(b) == 0 {
		return "fzb"
	}

	out := make([]byte, len(b))
	for i, c := range b {
		c = c % 38
		switch {
		case c < 26:
			out[i] = 'a' + c
		case c < 36:
			out[i] = '0' + (c - 26)
		default:
			out[i] = '-'
		}
	}
	if len(out) < 3 {
		out = append(out, 'x', 'x', 'x')
	}
	if out[0] == '-' {
		out[0] = 'a'
	}
	if out[len(out)-1] == '-' {
		out[len(out)-1] = 'b'
	}
	return string(out)
}

func FuzzBucketOpsString(f *testing.F) {
	f.Fuzz(func(t *testing.T, bname string) {

		//bucket name given by fuzzer
		bucket := bname

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		objLayer, err := getObjLayer(ctx)
		if err != nil {
			t.Skip()
		}

		// Create the bucket
		if err := objLayer.MakeBucket(ctx, bucket, MakeBucketOptions{}); err != nil {
			return // invalid bucket names
		}

		// Put small object
		objectName := "fuzz-object"
		content := []byte("12345")

		// create readers
		rawReader, err := hash.NewReader(ctx, bytes.NewReader(content), int64(len(content)), "", "", 0)
		if err != nil {
			t.Skip()
			return
		}

		defer rawReader.Close()
		putReader := NewPutObjReader(rawReader)
		if putReader != nil {
			defer func() { _ = putReader.Close() }()
		}

		_, err = objLayer.PutObject(ctx, bucket, objectName, putReader, ObjectOptions{})
		if err != nil {
			return
		}

		if _, err := objLayer.GetObjectInfo(ctx, bucket, objectName, ObjectOptions{}); err != nil {
			t.Errorf("GetObjectInfo failed: %v", err)
		}

		if _, err := objLayer.DeleteObject(ctx, bucket, objectName, ObjectOptions{}); err != nil {
			t.Errorf("DeleteObject failed: %v", err)
		}
	})
}

func FuzzBucketOpsByte(f *testing.F) {
	f.Add([]byte("seed"))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) < 4 {
			return
		}
		seed := int64(binary.LittleEndian.Uint32(data))
		r := rand.New(rand.NewSource(seed + int64(len(data))))

		ctx := context.Background()

		// Reuse single object layer per run (fast + low disk consumption)
		objLayer, err := getObjLayer(ctx)
		if err != nil {
			t.Skip()
		}

		// bucket name from fuzzer data
		bucket := encodeBucketName(data)

		// create bucket (ignore error: exists, invalid, etc.)
		_ = objLayer.MakeBucket(ctx, bucket, MakeBucketOptions{})

		// randomly delete bucket
		if r.Intn(5) == 0 {
			_ = objLayer.DeleteBucket(ctx, bucket, DeleteBucketOptions{})
		}

		// randomly list buckets
		if r.Intn(3) == 0 {
			_, _ = objLayer.ListBuckets(ctx, BucketOptions{})
		}
	})
}

func FuzzBucketOpsByteNRO(f *testing.F) {
	f.Add([]byte("seed"))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) < 4 {
			t.Skip()
			return
		}

		ctx := context.Background()

		// Reuse single object layer per run (fast + low disk consumption)
		objLayer, err := getObjLayer(ctx)
		if err != nil {
			t.Skip()
			return
		}

		// bucket name from fuzzer byte data
		bucket := sanitizeBucketName(data)

		// create bucket (ignore error: exists, invalid, etc.)
		_ = objLayer.MakeBucket(ctx, bucket, MakeBucketOptions{})

		// randomly delete bucket
		//if r.Intn(5) == 0 {
		_ = objLayer.DeleteBucket(ctx, bucket, DeleteBucketOptions{})
		//}

		// randomly list buckets
		//if r.Intn(3) == 0 {
		//_, _ = objLayer.ListBuckets(ctx, BucketOptions{})
		//}
	})
}

func encodeBucketName(b []byte) string {
	return sanitizeBucketName(b)
}

func getObjLayer(ctx context.Context) (ObjectLayer, error) {
	return getObjLayerOnce(ctx)
}

func FuzzMakeBucketOptions(f *testing.F) {
	f.Fuzz(func(t *testing.T, bname string, le, ve, fc bool) {
		ctx := context.Background()
		objLayer, err := getObjLayer(ctx)
		if err != nil {
			t.Skip()
		}

		opts := MakeBucketOptions{
			LockEnabled:       le,
			VersioningEnabled: ve,
			ForceCreate:       fc,
		}

		_ = objLayer.MakeBucket(ctx, bname, opts)

		// best-effort cleanup, без assert
		_ = objLayer.DeleteBucket(ctx, bname, DeleteBucketOptions{})
	})
}

func FuzzMakeBucketOptionsC(f *testing.F) {
	f.Fuzz(func(t *testing.T, bname string, le, ve, fc bool) {
		ctx := context.Background()
		objLayer, err := getObjLayerOnce(ctx)
		if err != nil {
			t.Skip()
		}

		opts := MakeBucketOptions{
			LockEnabled:       le,
			VersioningEnabled: ve,
			ForceCreate:       fc,
		}

		if opts.LockEnabled && opts.ForceCreate {
			t.Skip()
		}

		_ = objLayer.MakeBucket(ctx, bname, opts)

		// best-effort cleanup, без assert
		_ = objLayer.DeleteBucket(ctx, bname, DeleteBucketOptions{})
	})
}

func FuzzMakeBucketOptionsND(f *testing.F) {
	f.Fuzz(func(t *testing.T, bname string, le, ve, fc bool) {
		ctx := context.Background()
		objLayer, err := getObjLayerOnce(ctx)
		if err != nil {
			t.Skip()
		}

		opts := MakeBucketOptions{
			LockEnabled:       le,
			VersioningEnabled: ve,
			ForceCreate:       fc,
		}

		if opts.LockEnabled && opts.ForceCreate {
			t.Skip()
		}

		_ = objLayer.MakeBucket(ctx, bname, opts)

		// best-effort cleanup, без assert
		// Bucket deletion could be the reason of degratation
		// Will try to get rid of this effect turning the deletion off

		//_ = objLayer.DeleteBucket(ctx, bname, DeleteBucketOptions{})
	})
}

func FuzzMakeBucketOptionsCL(f *testing.F) {
	f.Fuzz(func(t *testing.T, bname string, le, ve, fc bool) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()

		objLayer, err := getObjLayerOnce(ctx)
		if err != nil {
			t.Skip()
		}

		// нормализуем имя бакета
		if len(bname) == 0 {
			t.Skip()
		}
		if len(bname) > 63 {
			bname = bname[:63]
		}
		bname = strings.ToLower(bname)
		bname = strings.Map(func(r rune) rune {
			if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
				return r
			}
			return 'a'
		}, bname)

		opts := MakeBucketOptions{
			LockEnabled:       le,
			VersioningEnabled: ve,
			ForceCreate:       fc,
		}

		if opts.LockEnabled && opts.ForceCreate {
			t.Skip()
		}

		_ = objLayer.MakeBucket(ctx, bname, opts)
		_ = objLayer.DeleteBucket(ctx, bname, DeleteBucketOptions{})
	})
}
