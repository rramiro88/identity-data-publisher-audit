package org.wso2.carbon.identity.data.publisher.audit.user.operation.model;

import com.google.gson.Gson;

import java.util.Map;

public class AttributesHolder {

    private Map claims;

    public AttributesHolder(Map claims) {

        this.claims = claims;
    }

    public Map getClaims() {

        return claims;
    }

    public void setClaims(Map claims) {

        this.claims = claims;
    }

    @Override
    public String toString() {
        return new Gson().toJson(claims);
    }
}
