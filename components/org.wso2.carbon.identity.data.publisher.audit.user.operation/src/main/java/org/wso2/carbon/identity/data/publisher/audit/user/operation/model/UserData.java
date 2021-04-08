/*
 * Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.data.publisher.audit.user.operation.model;

import org.wso2.carbon.identity.base.IdentityRuntimeException;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * POJO for storing user operation related data.
 *
 * @param <T1> The key type for the properties map
 * @param <T2> The value type for the properties map
 */
public class UserData<T1 extends Object, T2 extends Object> {
    private String action;
    private String username;
    private AttributesHolder attributes;
    private String userStoreDomain;
    private String tenantDomain;
    private String newRoleList;
    private String deletedRoleList;
    private Object claims;
    private String profile;
    private String actionHolder;
    private long actionTimestamp;
    private Map<T1, T2> parameters = new HashMap<>();

    public String getAction() {
        return action;
    }

    public void setAction(String action) {
        this.action = action;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public AttributesHolder getAttributes() {
        return attributes;
    }

    public void setAttributes(AttributesHolder attributes) {
        this.attributes = attributes;
    }

    public String getUserStoreDomain() {
        return userStoreDomain;
    }

    public void setUserStoreDomain(String userStoreDomain) {
        this.userStoreDomain = userStoreDomain;
    }

    public String getTenantDomain() {
        return tenantDomain;
    }

    public void setTenantDomain(String tenantDomain) {
        this.tenantDomain = tenantDomain;
    }

    public String getNewRoleList() {
        return newRoleList;
    }

    public void setNewRoleList(String newRoleList) {
        this.newRoleList = newRoleList;
    }

    public String getDeletedRoleList() {
        return deletedRoleList;
    }

    public void setDeletedRoleList(String deletedRoleList) {
        this.deletedRoleList = deletedRoleList;
    }

    public Object getClaims() {
        return claims;
    }

    public void setClaims(Object claims) {
        this.claims = claims;
    }

    public String getProfile() {
        return profile;
    }

    public void setProfile(String profile) {
        this.profile = profile;
    }

    public String getActionHolder() {
        return actionHolder;
    }

    public void setActionHolder(String actionHolder) {
        this.actionHolder = actionHolder;
    }

    public long getActionTimestamp() {
        return actionTimestamp;
    }

    public void setActionTimestamp(long actionTimestamp) {
        this.actionTimestamp = actionTimestamp;
    }

    public void addParameter(T1 key, T2 value) {
        if (this.parameters.containsKey(key)) {
            throw IdentityRuntimeException.error("Parameters map trying to override existing key " +
                    key);
        }
        parameters.put(key, value);
    }

    public void addParameters(Map<T1, T2> parameters) {
        for (Map.Entry<T1, T2> parameter : parameters.entrySet()) {
            if (this.parameters.containsKey(parameter.getKey())) {
                throw IdentityRuntimeException.error("Parameters map trying to override existing key "
                        + parameter.getKey());
            }
            parameters.put(parameter.getKey(), parameter.getValue());
        }
    }

    public Map<T1, T2> getParameters() {
        return Collections.unmodifiableMap(parameters);
    }

    public T2 getParameter(T1 key) {
        return parameters.get(key);
    }

}
