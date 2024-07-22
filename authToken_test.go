package main

import (
	"strconv"
	"testing"
)




func TestTokenAuthentication(t *testing.T){
	testConfig := &apiConfig{
		jwtSecret: "wuAFcAhBNZ9k26WGa8aGDjEDrOxOjOOaszZ96s2OaF2bRAKbqtKr5CxWlx3NKE6b",
	}
	type Params struct{
		ID int
	}
	testParams := Params{
		ID: 101,
	}

	signedStr, err := testConfig.generateAuthToken(testParams.ID)

	if err != nil {
		t.Errorf("error signing string:  \n%v", err)
	}
	
	claims, err := testConfig.parseJWTToken(signedStr)

	if err != nil {
		t.Error("error parsing token ", err)
	}

	if claims.Subject != strconv.Itoa(testParams.ID) {
		t.Errorf("expected %v, recieved %v", testParams.ID, claims.Subject)
	}

}