package spiderfoot

import (
	"fmt"
	"net/url"
)

func (e *SpiderfootEngine) ListModules() (string, error) {
	return e.apiGet("/modulelist", nil)
}

func (e *SpiderfootEngine) ListModuleGroups() (string, error) {
	return e.apiGet("/modulelist", url.Values{"groups": {"true"}})
}

func (e *SpiderfootEngine) DescribeModule(moduleName string) (string, error) {
	return e.apiGet(fmt.Sprintf("/module/%s", moduleName), nil)
}

func (e *SpiderfootEngine) GetRecommendedModules(targetType string) (string, error) {
	return e.apiGet("/modulelist/recommended", url.Values{"targettype": {targetType}})
}

func (e *SpiderfootEngine) ListScanResultTypes() (string, error) {
	return e.apiGet("/resulttypes", nil)
}
