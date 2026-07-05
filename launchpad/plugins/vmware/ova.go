package main

// OVA is a tar of an OVF descriptor + one or more VMDKs. Download whole
// thing, extract in memory, return (ovfXML, vmdkParts).
//
// The Ubuntu Noble OVA is ~500 MB, which is fine to hold in RAM once — we're
// running this on the launchpad operator's laptop, not on a memory-tight
// server. If this grows we'd stream via a scratch dir.

import (
	"archive/tar"
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
)

func downloadOVA(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("OVA download HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}

// extractOVA returns the OVF XML string and a map of vmdk-basename → bytes.
func extractOVA(data []byte) (string, map[string][]byte, error) {
	tr := tar.NewReader(bytes.NewReader(data))
	ovfXML := ""
	files := map[string][]byte{}
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", nil, err
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		buf, err := io.ReadAll(tr)
		if err != nil {
			return "", nil, err
		}
		switch {
		case strings.HasSuffix(hdr.Name, ".ovf"):
			ovfXML = string(buf)
		case strings.HasSuffix(hdr.Name, ".vmdk"):
			files[hdr.Name] = buf
		}
	}
	if ovfXML == "" {
		return "", nil, fmt.Errorf("no OVF descriptor in OVA")
	}
	if len(files) == 0 {
		return "", nil, fmt.Errorf("no VMDK entries in OVA")
	}
	return ovfXML, files, nil
}
