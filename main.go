package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
)

const (
	attrToken = "ATTRIBUTE"
	vendToken = "VENDOR"
	vendBegin = "BEGIN-VENDOR"
	vendEnd   = "END-VENDOR"
)

var (
	lastVend string
	lastVid  uint32
	useVid   bool
)

func convertType(t string) string {
	for i, v := range t {
		if v == '[' || v == ']' {
			t = t[:i]
			break
		}
	}
	switch strings.ToLower(t) {
	case "abinary":
		return "DTypeRaw"
	case "byte":
		return "DTypeByte"
	case "combo-ip":
		return "DTypeIP"
	case "date":
		return "DTypeTime"
	case "ether":
		return "DTypeEth"
	case "extended":
		return "DTypeEXT"
	case "ifid":
		return "DTypeIfID"
	case "integer":
		return "DTypeInt"
	case "integer64":
		return "DTypeInt64"
	case "ipaddr":
		return "DTypeIP4"
	case "ipv4prefix":
		return "DTypeIP4Pfx"
	case "ipv6addr":
		return "DTypeIP6"
	case "ipv6prefix":
		return "DTypeIP6Pfx"
	case "long-extended":
		return "DTypeLongEXT"
	case "octets":
		return "DTypeRaw"
	case "short":
		return "DTypeShort"
	case "signed":
		return "DTypeSInt"
	case "string":
		return "DTypeString"
	case "tlv":
		return "DTypeTLV"
	case "vsa":
		return "DTypeVSA"
	default:
		return "DTypeRaw"
	}
}

func parseFlags(f string) (used bool, tag bool, enc string) {
	for _, v := range strings.Split(strings.ToLower(f), ",") {
		switch v {
		case "has_tag":
			used = true
			tag = true
		case "encrypt=1":
			used = true
			enc = "AttrEncUsr"
		case "encrypt=2":
			used = true
			enc = "AttrEncTun"
		case "encrypt=3":
			used = true
			enc = "AttrEncAsc"
		}
	}
	if used && enc == "" {
		enc = "AttrEncNone"
	}
	return
}

func main() {
	if len(os.Args) != 2 {
		log.Fatal("Usage: ", os.Args[0], " radius.dict")
	}
	file, err := os.Open(os.Args[1])
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		s := strings.TrimSpace(scanner.Text())
		for i, v := range s {
			if v == '#' {
				s = s[:i]
				break
			}
		}
		ss := strings.Fields(s)
		if len(ss) < 1 {
			continue
		}
		switch ss[0] {
		case attrToken:
			// noop
		case vendToken:
			if len(ss) < 3 {
				log.Fatal("Invalid ", vendToken)
			}
			lastVend = ss[1]
			v, e := strconv.ParseUint(ss[2], 0, 32)
			if e != nil {
				log.Fatal(e)
			}
			lastVid = uint32(v)
			continue
		case vendBegin:
			if len(ss) != 2 {
				log.Fatal("Invalid ", vendBegin)
			}
			if ss[1] != lastVend {
				log.Fatal("Unknown vendor ", ss[1])
			}
			useVid = true
			continue
		case vendEnd:
			if len(ss) != 2 {
				log.Fatal("Invalid ", vendEnd)
			}
			if ss[1] != lastVend {
				log.Fatal("Unknown vendor ", ss[1])
			}
			lastVend = ""
			lastVid = 0
			useVid = false
			continue
		default:
			continue
		}
		var (
			used, tag bool
			enc string
		)
		if len(ss) > 4 {
			used, tag, enc = parseFlags(ss[4])
		} else {
			used = false
			tag = false
			enc = "AttrEncNone"
		}
		an := ss[1]
		v, e := strconv.ParseUint(ss[2], 0, 8)
		if e != nil {
			log.Print(e)
			continue
		}
		av := byte(v)
		at := convertType(ss[3])
		if !useVid { // Plain attr
			if !used{
				fmt.Printf("MustAddAttr(\"%s\", %d, %s)\n", an, av, at)
			} else {
				if tag {
					fmt.Printf("MustAddAttrEncTag(\"%s\", %d, %s, %s)\n", an, av, at, enc)
				} else {
					fmt.Printf("MustAddAttrEnc(\"%s\", %d, %s, %s)\n", an, av, at, enc)
				}
			}
		} else { // VSA
			if !used{
				fmt.Printf("MustAddVSA(\"%s\", %d, %d, %s)\n", an, lastVid, av, at)
			} else {
				if tag {
					fmt.Printf("MustAddVSAEncTag(\"%s\", %d, %d, %s, %s)\n", an, lastVid, av, at, enc)
				} else {
					fmt.Printf("MustAddVSAEnc(\"%s\", %d, %d, %s, %s)\n", an, lastVid, av, at, enc)
				}
			}
		}
	}
	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}
}
