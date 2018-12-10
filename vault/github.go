package vault

import (
	"fmt"
	"strings"
)

func githubMapId(backend string, name string, mapType string) string {
	return fmt.Sprintf("auth/%s/map/%s/%s", strings.Trim(backend, "/"), mapType, name)
}

func githubMappingPath(mapId string, mapType string) string {
	name := mapId[strings.LastIndex(mapId, "/")+1:]
	mapPath := "/map/" + mapType + "/" + name
	s := strings.Replace(mapId, mapPath, "", -1)

	return strings.Replace(s, "auth/", "", -1)
}
