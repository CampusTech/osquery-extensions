// Command mac_enclosure_color is an osquery extension that exposes a
// mac_enclosure_color table returning the running Mac's enclosure color.
//
// Data sources:
//   - MobileGestalt (private dylib) for ProductType and DeviceEnclosureColor.
//   - system_profiler (public CLI) for the human "Model Name" string, since
//     MobileGestalt's marketing-name keys return the OS name ("macOS") on
//     recent macOS versions.
//
// Build:
//   GOOS=darwin go build -o mac_enclosure_color.ext
//
// Run standalone (for testing):
//   osqueryi --extension ./mac_enclosure_color.ext
//
// Deploy with Fleet's fleetd / orbit by packaging the binary alongside the
// agent and letting orbit auto-load extensions in its extensions dir.
package main

/*
#cgo LDFLAGS: -framework CoreFoundation
#include <CoreFoundation/CoreFoundation.h>
#include <dlfcn.h>
#include <stdlib.h>

typedef CFTypeRef (*MGCopyAnswerFn)(CFStringRef);

static MGCopyAnswerFn mg_copy_answer_fn = NULL;

static int load_mg(void) {
    if (mg_copy_answer_fn) return 1;
    void* h = dlopen("/usr/lib/libMobileGestalt.dylib", RTLD_LAZY);
    if (!h) return 0;
    mg_copy_answer_fn = (MGCopyAnswerFn)dlsym(h, "MGCopyAnswer");
    return mg_copy_answer_fn != NULL ? 1 : 0;
}

// mg_int returns the integer answer for key, or -1 if missing/wrong type.
static int mg_int(const char* key) {
    if (!mg_copy_answer_fn) return -1;
    CFStringRef k = CFStringCreateWithCString(NULL, key, kCFStringEncodingUTF8);
    if (!k) return -1;
    CFTypeRef v = mg_copy_answer_fn(k);
    CFRelease(k);
    if (!v) return -1;
    int result = -1;
    CFTypeID tid = CFGetTypeID(v);
    if (tid == CFNumberGetTypeID()) {
        CFNumberGetValue((CFNumberRef)v, kCFNumberIntType, &result);
    } else if (tid == CFStringGetTypeID()) {
        char buf[64];
        if (CFStringGetCString((CFStringRef)v, buf, sizeof(buf), kCFStringEncodingUTF8)) {
            result = atoi(buf);
        }
    }
    CFRelease(v);
    return result;
}

// mg_string returns a malloc'd UTF-8 copy of the string answer for key, or NULL.
static char* mg_string(const char* key) {
    if (!mg_copy_answer_fn) return NULL;
    CFStringRef k = CFStringCreateWithCString(NULL, key, kCFStringEncodingUTF8);
    if (!k) return NULL;
    CFTypeRef v = mg_copy_answer_fn(k);
    CFRelease(k);
    if (!v) return NULL;
    char* result = NULL;
    if (CFGetTypeID(v) == CFStringGetTypeID()) {
        CFIndex len = CFStringGetMaximumSizeForEncoding(
            CFStringGetLength((CFStringRef)v), kCFStringEncodingUTF8) + 1;
        result = (char*)malloc((size_t)len);
        if (result && !CFStringGetCString((CFStringRef)v, result, len, kCFStringEncodingUTF8)) {
            free(result);
            result = NULL;
        }
    }
    CFRelease(v);
    return result;
}
*/
import "C"

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os/exec"
	"time"
	"unsafe"

	osquery "github.com/osquery/osquery-go"
	"github.com/osquery/osquery-go/plugin/table"
)

func init() {
	C.load_mg()
}

func mgInt(key string) (int, bool) {
	ck := C.CString(key)
	defer C.free(unsafe.Pointer(ck))
	v := C.mg_int(ck)
	if v < 0 {
		return 0, false
	}
	return int(v), true
}

func mgString(key string) (string, bool) {
	ck := C.CString(key)
	defer C.free(unsafe.Pointer(ck))
	cs := C.mg_string(ck)
	if cs == nil {
		return "", false
	}
	defer C.free(unsafe.Pointer(cs))
	return C.GoString(cs), true
}

// modelNameViaSystemProfiler returns the "Model Name" string from
// `system_profiler SPHardwareDataType -json`, e.g. "MacBook Pro".
// MobileGestalt does not expose this on recent macOS.
func modelNameViaSystemProfiler() string {
	out, err := exec.Command("/usr/sbin/system_profiler", "SPHardwareDataType", "-json").Output()
	if err != nil {
		return ""
	}
	var parsed struct {
		SPHardwareDataType []struct {
			MachineName string `json:"machine_name"`
		} `json:"SPHardwareDataType"`
	}
	if err := json.Unmarshal(out, &parsed); err != nil {
		return ""
	}
	if len(parsed.SPHardwareDataType) == 0 {
		return ""
	}
	return parsed.SPHardwareDataType[0].MachineName
}

func generate(ctx context.Context, qc table.QueryContext) ([]map[string]string, error) {
	productType, _ := mgString("ProductType")
	code, codeKnown := mgInt("DeviceEnclosureColor")
	model := modelNameViaSystemProfiler()
	color := resolveColor(productType, model, code, codeKnown)

	row := map[string]string{
		"color":        color,
		"color_code":   "",
		"model":        model,
		"product_type": productType,
	}
	if codeKnown {
		row["color_code"] = fmt.Sprintf("%d", code)
	}
	return []map[string]string{row}, nil
}

func main() {
	socket := flag.String("socket", "", "Path to the osquery extension socket")
	timeout := flag.Int("timeout", 3, "Seconds to wait for a successful connection")
	interval := flag.Int("interval", 3, "Seconds between connection checks")
	verbose := flag.Bool("verbose", false, "Enable verbose extension logging")
	flag.Parse()
	_ = *verbose

	if *socket == "" {
		log.Fatalln("--socket is required")
	}

	server, err := osquery.NewExtensionManagerServer(
		"mac_enclosure_color",
		*socket,
		osquery.ServerTimeout(time.Duration(*timeout)*time.Second),
		osquery.ServerPingInterval(time.Duration(*interval)*time.Second),
	)
	if err != nil {
		log.Fatalf("error creating extension manager: %s", err)
	}

	columns := []table.ColumnDefinition{
		table.TextColumn("color"),
		table.TextColumn("color_code"),
		table.TextColumn("model"),
		table.TextColumn("product_type"),
	}
	server.RegisterPlugin(table.NewPlugin("mac_enclosure_color", columns, generate))

	if err := server.Run(); err != nil {
		log.Fatalln(err)
	}
}
