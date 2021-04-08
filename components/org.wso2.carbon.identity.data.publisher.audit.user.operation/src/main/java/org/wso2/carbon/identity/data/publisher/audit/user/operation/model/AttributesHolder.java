package org.wso2.carbon.identity.data.publisher.audit.user.operation.model;

import com.google.gson.Gson;

import java.util.Map;

public class AttributesHolder {

    private Map attributesMap;

    public AttributesHolder(Map attributes) {

        this.attributesMap = attributes;
    }

    public Map getAttributesMap() {

        return attributesMap;
    }

    public void setAttributesMap(Map attributesMap) {

        this.attributesMap = attributesMap;
    }

    @Override
    public String toString() {
        return new Gson().toJson(attributesMap);
    }
}
