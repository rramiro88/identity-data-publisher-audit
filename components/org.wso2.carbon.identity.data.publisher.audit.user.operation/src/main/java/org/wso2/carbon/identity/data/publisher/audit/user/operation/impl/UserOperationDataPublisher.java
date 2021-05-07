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

package org.wso2.carbon.identity.data.publisher.audit.user.operation.impl;

import com.google.gson.Gson;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.slf4j.MDC;
import org.wso2.carbon.context.CarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.model.User;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.data.publisher.audit.common.AuditDataPublisherConstants;
import org.wso2.carbon.identity.data.publisher.audit.common.AuditDataPublisherUtils;
import org.wso2.carbon.identity.data.publisher.audit.user.operation.internal.UserOperationDataPublisherDataHolder;
import org.wso2.carbon.identity.data.publisher.audit.user.operation.model.AttributesHolder;
import org.wso2.carbon.identity.data.publisher.audit.user.operation.model.UserData;
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.identity.event.handler.AbstractEventHandler;
import org.wso2.carbon.identity.recovery.IdentityRecoveryConstants;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;

import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Publisher for user related operations.
 */
public class UserOperationDataPublisher extends AbstractEventHandler {

    private static final Log log = LogFactory.getLog(UserOperationDataPublisher.class);

    @Override
    public void handleEvent(Event event) throws IdentityEventException {

        switch (event.getEventName()) {
            case IdentityEventConstants.Event.POST_ADD_USER:
                handleAddUser(event);
                break;
            case IdentityEventConstants.Event.POST_DELETE_USER:
                handleDeleteUser(event);
                break;
            case IdentityEventConstants.Event.POST_UPDATE_CREDENTIAL:
            case IdentityEventConstants.Event.POST_UPDATE_CREDENTIAL_BY_ADMIN:
                handleUpdateCredential(event);
                break;
            case "POST_LOCK_ACCOUNT":
            case "POST_UNLOCK_ACCOUNT":
                handleLockUnlock(event);
                break;
            case "PRE_ACCOUNT_RECOVERY":
                handleSendRecoveryNotification(event);
                break;
            case "POST_GET_USER_RECOVERY_DATA":
                handleRecoveryAttempt(event);
                break;
            default:
                if (log.isDebugEnabled()) {
                    log.debug("Ignored unsupported event " + event.getEventName());
                }
        }
    }

    /**
     * This will publish an event only if the attempt is failed
     * @param event
     */
    private void handleRecoveryAttempt(Event event) {

        UserData userData = new UserData();
        userData.setAttributes(new AttributesHolder(new HashMap()));
        userData.setAction(event.getEventName());
        userData.setActionTimestamp(System.currentTimeMillis());
        userData.setAction(event.getEventName());
        userData.setUsername((String) event.getEventProperties().get(IdentityEventConstants.EventProperty.USER_NAME));

        // Setting the action holder
        String actionHolderTenantDomain = CarbonContext.getThreadLocalCarbonContext().getTenantDomain();
        String actionHolder = CarbonContext.getThreadLocalCarbonContext().getUsername();
        userData.setActionHolder(AuditDataPublisherUtils.getActionHolder(actionHolder, actionHolderTenantDomain));

        // Adding additional properties
        userData.addParameter(AuditDataPublisherConstants.PUBLISHING_TENANT_DOMAINS, new String[]{"carbon.super"});
        if (event.getEventProperties().get("OPERATION_STATUS").equals(false)) {

            IdentityRecoveryConstants.ErrorMessages errorMessage =
                    (IdentityRecoveryConstants.ErrorMessages) event.getEventProperties().get("OPERATION_DESCRIPTION");
            if (errorMessage.equals(IdentityRecoveryConstants.ErrorMessages.ERROR_CODE_EXPIRED_CODE)
                    || errorMessage.equals(IdentityRecoveryConstants.ErrorMessages.ERROR_CODE_INVALID_CODE)) {
                userData.getAttributes().getAttributesMap().put("status", "FAILED");
                userData.getAttributes().getAttributesMap().put("reason",
                        event.getEventProperties().get("OPERATION_DESCRIPTION"));
                publishUserData(userData, AuditDataPublisherConstants.PASSWORD_RECOVERY_EVENT_STREAM_NAME);
            }
        }

    }

    /**
     * Handles PRE_ACCOUNT_RECOVERY event
     *
     * @param event
     */
    private void handleSendRecoveryNotification(Event event) {

        UserData userData = getGeneralUserData(event);
        String username = ((User) event.getEventProperties().get("USER")).getUserName();
        userData.setUsername(username);
        buildAndSetAttributesMap(event, userData);
        retrieveAndSetRequestData(userData);
        String type = getNotificationTypeFromEvent(event);
        userData.getAttributes().getAttributesMap().put(Constants.NOTIFICATION_CHANNEL, type);
        publishUserData(userData, AuditDataPublisherConstants.PASSWORD_RECOVERY_EVENT_STREAM_NAME);
    }

    private String getNotificationTypeFromEvent(Event event) {

        Object notificationChannel = ((List) event.getEventProperties().get(Constants.NOTIFICATION_CHANNEL)).get(0);
        Gson gson = new Gson();
        String json = gson.toJson(notificationChannel);
        Map map = gson.fromJson(json, Map.class);
        String type = (String)map.get("type");
        return type;
    }

    /**
     * Handles POST_ADD_USER event.
     *
     * @param event The event related to the add user
     */
    private void handleAddUser(Event event) {

        UserData userData = getGeneralUserData(event);
        userData.setProfile((String) event.getEventProperties().get(IdentityEventConstants.EventProperty.PROFILE_NAME));

        // Adding new roles
        String[] roles = (String[]) event.getEventProperties().get(IdentityEventConstants.EventProperty.ROLE_LIST);
        if (roles != null && roles.length > 0) {
            userData.setNewRoleList(AuditDataPublisherUtils.getCommaSeparatedList(roles));
        }

        // Adding new claims
        Map claims = (Map) event.getEventProperties().get(IdentityEventConstants.EventProperty.USER_CLAIMS);
        if (claims == null) {
            claims = new HashMap();
        }
        userData.setClaims(claims);
        publishUserData(userData, AuditDataPublisherConstants.OVERALL_USER_DATA_EVENT_STREAM_NAME);
    }

    /**
     * Handles POST_DELETE_USER event.
     *
     * @param event The event related to the delete user
     */
    private void handleDeleteUser(Event event) {

        UserData userData = getGeneralUserData(event);
        publishUserData(userData, AuditDataPublisherConstants.OVERALL_USER_DATA_EVENT_STREAM_NAME);
    }

    /**
     * Handle credential update related events.
     * <p>
     * Handles both POST_UPDATE_CREDENTIAL and POST_UPDATE_CREDENTIAL_BY_ADMIN
     *
     * @param event The event related to the credential update
     */
    private void handleUpdateCredential(Event event) {

        UserData userData = getGeneralUserData(event);

        buildAndSetAttributesMap(event, userData);
        retrieveAndSetRequestData(userData);

        publishUserData(userData, AuditDataPublisherConstants.PASSWORD_RECOVERY_EVENT_STREAM_NAME);
    }

    private void retrieveAndSetRequestData(UserData userData) {
        String remoteAddress = MDC.get("remoteAddress");
        String browserAgent = MDC.get("User-Agent");

        userData.getAttributes().getAttributesMap().put("ipAddress", remoteAddress);
        userData.getAttributes().getAttributesMap().put("browserAgent", browserAgent);

    }

    private void buildAndSetAttributesMap(Event event, UserData userData) {

        UserStoreManager userStoreManager = (UserStoreManager) event.getEventProperties()
                .get(IdentityEventConstants.EventProperty.USER_STORE_MANAGER);
        Map<String, String> attributesMap = new HashMap<>();
        try {
            Map<String, String> claimValues = userStoreManager.getUserClaimValues(userData.getUsername(),
                    new String[]{Constants.ACCOUNT_NUMBER, Constants.USER_ID}, "default");
            attributesMap.put(Constants.ACCOUNT_NUMBER_ATTRIBUTE_NAME, claimValues.get(Constants.ACCOUNT_NUMBER));
            attributesMap.put(Constants.USER_ID_ATTRIBUTE_NAME, claimValues.get(Constants.USER_ID));
            userData.setAttributes(new AttributesHolder(attributesMap));
        } catch (UserStoreException e) {
            log.error("Error getting claims", e);
        }

    }

    /**
     * Handles POST_SET_USER_CLAIM and POST_SET_USER_CLAIMS events.
     *
     * @param event The event related to the set user claims.
     */
    private void handleLockUnlock(Event event) {

        UserData userData = getGeneralUserData(event);

        // Adding updated claims
        Map claims = (Map) event.getEventProperties().get(IdentityEventConstants.EventProperty.USER_CLAIMS);
        if (claims == null) {
            claims = new HashMap();
        }
        AttributesHolder claimsHolder = new AttributesHolder(claims);
        userData.setClaims(claimsHolder);
        UserStoreManager userStoreManager = (UserStoreManager) event.getEventProperties()
                .get(IdentityEventConstants.EventProperty.USER_STORE_MANAGER);
        try {
            Map<String, String> attributesMap = new HashMap<>();
            Map<String, String> claimValues = userStoreManager.getUserClaimValues(userData.getUsername(),
                    new String[]{
                            Constants.ACCOUNT_NUMBER, Constants.LOCKED_REASON,
                            Constants.ACCOUNT_LOCK,Constants.USER_ID
                    }, "default");

            attributesMap.put(Constants.ACCOUNT_LOCK_ATTRIBUTE_NAME, claimValues.get(Constants.ACCOUNT_LOCK));
            if (Objects.equals(Constants.PATRON_USER_STORE, userData.getUserStoreDomain())) {
                attributesMap.put(Constants.ACCOUNT_NUMBER_ATTRIBUTE_NAME, claimValues.get(Constants.ACCOUNT_NUMBER));
            }
            attributesMap.put(Constants.USER_ID_ATTRIBUTE_NAME, claimValues.get(Constants.USER_ID));
            attributesMap.put(Constants.LOCKED_REASON_ATTRIBUTE_NAME, claimValues.get(Constants.LOCKED_REASON));
            userData.setAttributes(new AttributesHolder(attributesMap));
            retrieveAndSetRequestData(userData);
            publishUserData(userData, AuditDataPublisherConstants.OVERALL_USER_DATA_EVENT_STREAM_NAME);
        } catch (UserStoreException e) {
            log.error("Error getting claims", e);
        }
    }

    /**
     * Publish user related data to IS Analytics.
     *
     * @param userData   The user data to be published
     * @param streamName
     */
    private void publishUserData(UserData userData, String streamName) {

        Object[] payloadData = new Object[11];
        payloadData[0] = userData.getAction();
        payloadData[1] = userData.getUsername();
        payloadData[2] = userData.getAttributes();
        payloadData[3] = userData.getUserStoreDomain();
        payloadData[4] = userData.getTenantDomain();
        payloadData[5] = userData.getNewRoleList();
        payloadData[6] = userData.getDeletedRoleList();
        payloadData[7] = userData.getClaims();
        payloadData[8] = userData.getProfile();
        payloadData[9] = userData.getActionHolder();
        payloadData[10] = userData.getActionTimestamp();

        String[] publishingDomainsArray = (String[]) userData.getParameter(AuditDataPublisherConstants.PUBLISHING_TENANT_DOMAINS);
        Set<String> publishingDomains = new HashSet<>(Arrays.asList(publishingDomainsArray));
        if (!publishingDomains.isEmpty()) {
            try {
                FrameworkUtils.startTenantFlow(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
                for (String publishingDomain : publishingDomains) {
                    Object[] metadataArray = AuditDataPublisherUtils.getMetaDataArray(publishingDomain);
                    org.wso2.carbon.databridge.commons.Event event = new org.wso2.carbon.databridge.commons.Event
                            (streamName, System
                                    .currentTimeMillis(), metadataArray, null, payloadData);
                    UserOperationDataPublisherDataHolder.getInstance().getPublisherService().publish(event);
                    if (log.isDebugEnabled()) {
                        log.debug("Sending out event : " + event.toString());
                    }
                }
            } finally {
                FrameworkUtils.endTenantFlow();
            }
        }
    }

    /**
     * Get the general user related data from event.
     *
     * @return General user related data in the event.
     */
    private UserData getGeneralUserData(Event event) {

        UserData userData = new UserData();
        userData.setActionTimestamp(System.currentTimeMillis());
        userData.setAction(event.getEventName());
        userData.setUsername((String) event.getEventProperties().get(IdentityEventConstants.EventProperty.USER_NAME));

        // Setting the action holder
        String actionHolderTenantDomain = CarbonContext.getThreadLocalCarbonContext().getTenantDomain();
        String actionHolder = CarbonContext.getThreadLocalCarbonContext().getUsername();
        userData.setActionHolder(AuditDataPublisherUtils.getActionHolder(actionHolder, actionHolderTenantDomain));

        // Setting the tenant domain
        UserStoreManager userStoreManager = (UserStoreManager) event.getEventProperties()
                .get(IdentityEventConstants.EventProperty.USER_STORE_MANAGER);
        int userTenantId = userStoreManager.getRealmConfiguration().getTenantId();
        String userTenantDomain = IdentityTenantUtil.getTenantDomain(userTenantId);
        userData.setTenantDomain(userTenantDomain);

        // Setting the user store domain
        String userStoreDomain = UserCoreUtil.getDomainName(userStoreManager.getRealmConfiguration());
        if (StringUtils.isEmpty(userStoreDomain)) {
            userStoreDomain = UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME;
        }
        userData.setUserStoreDomain(userStoreDomain);

        // Adding additional properties
        userData.addParameter(AuditDataPublisherConstants.PUBLISHING_TENANT_DOMAINS,
                AuditDataPublisherUtils.getTenantDomains(actionHolderTenantDomain, userTenantDomain));

        return userData;
    }

    @Override
    public String getName() {

        return AuditDataPublisherConstants.USER_MGT_DAS_DATA_PUBLISHER;
    }
}
