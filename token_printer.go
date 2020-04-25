package main

import (
	"fmt"
	"sort"
	"strings"
	"syscall"

	"golang.org/x/sys/windows"
)

func printTokenInformation(token windows.Token) {
	fmt.Println("Token:", token)
	if tg, err := token.GetTokenGroups(); err == nil {
		for _, g := range tg.AllGroups() {
			name, domain, err := loopUpAccountName(g.Sid)
			if err != nil {
				fmt.Println("error", err)
			}
			fmt.Printf("  %-80s %s\n", domain+"/"+name, getAttributeString(g.Attributes))
		}
	}
	if pri, err := token.GetTokenPrimaryGroup(); err == nil {
		fmt.Printf("  Primary Group: %v\n", pri)
	}
	if tu, err := token.GetTokenUser(); err == nil {
		fmt.Printf("  Token User: %v\n", tu)
	}
	if pd, err := token.GetUserProfileDirectory(); err == nil {
		fmt.Printf("  Prifile Directory: %s\n", pd)
	}
	fmt.Printf("  elavated: %v\n", token.IsElevated())
}

var seLable map[uint32]string = map[uint32]string{
	windows.SE_GROUP_MANDATORY:          "SE_GROUP_MANDATORY",
	windows.SE_GROUP_ENABLED_BY_DEFAULT: "SE_GROUP_ENABLED_BY_DEFAULT",
	windows.SE_GROUP_ENABLED:            "SE_GROUP_ENABLED",
	windows.SE_GROUP_OWNER:              "SE_GROUP_OWNER",
	windows.SE_GROUP_USE_FOR_DENY_ONLY:  "SE_GROUP_USE_FOR_DENY_ONLY",
	windows.SE_GROUP_INTEGRITY:          "SE_GROUP_INTERGRITY",
	windows.SE_GROUP_INTEGRITY_ENABLED:  "SE_GROUP_INTEGRITY_ENABLED",
	windows.SE_GROUP_LOGON_ID:           "SE_GROUP_LOGON_ID",
	windows.SE_GROUP_RESOURCE:           "SE_GROUP_RESOURCE",
}

func getAttributeString(attr uint32) string {
	var attrStr []string
	for i, s := range seLable {
		if attr&i == i {
			attrStr = append(attrStr, s)
		}
	}
	sort.Sort(sort.StringSlice(attrStr))
	return strings.Join(attrStr, " | ")
}

func loopUpAccountName(sid *windows.SID) (string, string, error) {
	nameBuff := make([]uint16, 256)
	domainBuff := make([]uint16, 256)
	nameLen := uint32(len(nameBuff) * 2)
	domainLen := uint32(len(domainBuff) * 2)
	var use uint32
	if err := windows.LookupAccountSid(nil, sid, &nameBuff[0], &nameLen, &domainBuff[0], &domainLen, &use); err != nil {
		return "", "", err
	}
	return syscall.UTF16ToString(nameBuff[:nameLen]), syscall.UTF16ToString(domainBuff[:domainLen]), nil
}
