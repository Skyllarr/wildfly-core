/*
Copyright 2020 Red Hat, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
 */
package org.wildfly.extension.elytron;

import org.jboss.as.controller.client.helpers.ClientConstants;
import org.jboss.as.subsystem.test.AbstractSubsystemTest;
import org.jboss.as.subsystem.test.KernelServices;
import org.jboss.dmr.ModelNode;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import static org.jboss.as.controller.descriptions.ModelDescriptionConstants.FAILED;
import static org.jboss.as.controller.descriptions.ModelDescriptionConstants.FAILURE_DESCRIPTION;
import static org.jboss.as.controller.descriptions.ModelDescriptionConstants.OPERATION_REQUIRES_RELOAD;
import static org.jboss.as.controller.descriptions.ModelDescriptionConstants.OUTCOME;
import static org.jboss.as.controller.descriptions.ModelDescriptionConstants.RESPONSE_HEADERS;
import static org.jboss.as.controller.descriptions.ModelDescriptionConstants.SUCCESS;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class DynamicSSLContextTestCase extends AbstractSubsystemTest {

    private static final String DYNAMIC_SSL_CLIENT_CONTEXT_NAME = "dcsc";
    private static final String SUBSYSTEM = "subsystem";
    private static final String ELYTRON = "elytron";

    public DynamicSSLContextTestCase() {
        super(ElytronExtension.SUBSYSTEM_NAME, new ElytronExtension());
    }

    private static KernelServices services = null;

    @Before
    public void initServices() throws Exception {
        services = super.createKernelServicesBuilder(new TestEnvironment()).setSubsystemXmlResource("authentication-client.xml").build();
        if (!services.isSuccessfulBoot()) {
            Assert.fail(services.getBootError().toString());
        }
    }

    @Test
    public void testAddDynamicClientSSLContext() {
        addDynamicSSLClientContext();
        readDynamicSSLCientContextResource();
    }

    @Test
    public void testRemoveDynamicClientSSLContext() {
        addDynamicSSLClientContext();
        ModelNode operation = new ModelNode();
        operation.get(ClientConstants.OP_ADDR)
                .add(SUBSYSTEM, ELYTRON).add(ElytronDescriptionConstants.DYNAMIC_CLIENT_SSL_CONTEXT, DYNAMIC_SSL_CLIENT_CONTEXT_NAME);
        operation.get(ClientConstants.OP).set(ClientConstants.REMOVE_OPERATION);
        assertSuccess(services.executeOperation(operation));

        operation = new ModelNode();
        operation.get(ClientConstants.OP_ADDR)
                .add(SUBSYSTEM, ELYTRON).add(ElytronDescriptionConstants.DYNAMIC_CLIENT_SSL_CONTEXT, DYNAMIC_SSL_CLIENT_CONTEXT_NAME);
        operation.get(ClientConstants.OP).set(ClientConstants.READ_RESOURCE_OPERATION);
        assertFailed(services.executeOperation(operation));
    }

    @Test
    public void testUpdateDynamicClientSSLContext() {
        addDynamicSSLClientContext();
        ModelNode operation = new ModelNode();
        operation.get(ClientConstants.OP_ADDR)
                .add(SUBSYSTEM, ELYTRON).add(ElytronDescriptionConstants.DYNAMIC_CLIENT_SSL_CONTEXT, DYNAMIC_SSL_CLIENT_CONTEXT_NAME);
        operation.get(ClientConstants.OP).set(ClientConstants.WRITE_ATTRIBUTE_OPERATION);
        operation.get(ClientConstants.NAME).set(ElytronDescriptionConstants.AUTHENTICATION_CONTEXT);
        operation.get(ClientConstants.VALUE).set("base");
        assertSuccess(services.executeOperation(operation));

        operation = new ModelNode();
        operation.get(ClientConstants.OP_ADDR)
                .add(SUBSYSTEM, ELYTRON).add(ElytronDescriptionConstants.DYNAMIC_CLIENT_SSL_CONTEXT, DYNAMIC_SSL_CLIENT_CONTEXT_NAME);
        operation.get(ClientConstants.OP).set(ClientConstants.READ_RESOURCE_OPERATION);
        ModelNode result = assertSuccess(services.executeOperation(operation)).get(ClientConstants.RESULT);
        assertEquals("base", result.get(ElytronDescriptionConstants.AUTHENTICATION_CONTEXT).asString());
    }

    @Test
    public void testAddDynamicClientSSLContextWithoutACThrowsEx() {
        ModelNode operation = new ModelNode();
        operation.get(ClientConstants.OP_ADDR)
                .add(SUBSYSTEM, ELYTRON).add(ElytronDescriptionConstants.DYNAMIC_CLIENT_SSL_CONTEXT, DYNAMIC_SSL_CLIENT_CONTEXT_NAME);
        operation.get(ClientConstants.OP).set(ClientConstants.ADD);

        ModelNode result = services.executeOperation(operation);
        assertFailed(result);
        String failureDescription = result.get(FAILURE_DESCRIPTION).asString();
        assertTrue(failureDescription.contains("WFLYCTL0412") && failureDescription.contains("WFLYCTL0180"));
    }

    @Test
    public void testAddDynamicClientSSLContextAsDefaultSSLContext() {
        addDynamicSSLClientContext();
        ModelNode operation = new ModelNode();
        operation.get(ClientConstants.OP_ADDR).add(SUBSYSTEM, ELYTRON);
        operation.get(ClientConstants.OP).set(ClientConstants.WRITE_ATTRIBUTE_OPERATION);
        operation.get(ClientConstants.NAME).set(ElytronDescriptionConstants.DEFAULT_SSL_CONTEXT);
        operation.get(ClientConstants.VALUE).set(DYNAMIC_SSL_CLIENT_CONTEXT_NAME);
        ModelNode result = assertSuccess(services.executeOperation(operation));
        result.has(RESPONSE_HEADERS, OPERATION_REQUIRES_RELOAD);
        operation = new ModelNode();
        operation.get(ClientConstants.OP_ADDR).add(SUBSYSTEM, ELYTRON);
        operation.get(ClientConstants.OP).set(ClientConstants.READ_RESOURCE_OPERATION);
        result = assertSuccess(services.executeOperation(operation)).get(ClientConstants.RESULT);
        assertEquals(DYNAMIC_SSL_CLIENT_CONTEXT_NAME, result.get(ElytronDescriptionConstants.DEFAULT_SSL_CONTEXT).asString());
    }

    private ModelNode assertSuccess(ModelNode response) {
        if (!response.get(OUTCOME).asString().equals(SUCCESS)) {
            Assert.fail(response.toJSONString(false));
        }
        return response;
    }

    private ModelNode assertFailed(ModelNode response) {
        if (!response.get(OUTCOME).asString().equals(FAILED)) {
            Assert.fail(response.toJSONString(false));
        }
        return response;
    }

    private void addDynamicSSLClientContext() {
        ModelNode operation = new ModelNode();
        operation.get(ClientConstants.OP_ADDR)
                .add(SUBSYSTEM, ELYTRON).add(ElytronDescriptionConstants.DYNAMIC_CLIENT_SSL_CONTEXT, DYNAMIC_SSL_CLIENT_CONTEXT_NAME);
        operation.get(ClientConstants.OP).set(ClientConstants.ADD);
        operation.get(ElytronDescriptionConstants.AUTHENTICATION_CONTEXT).set("ac");
        assertSuccess(services.executeOperation(operation));
    }

    private void readDynamicSSLCientContextResource() {
        ModelNode operation = new ModelNode();
        operation.get(ClientConstants.OP_ADDR)
                .add(SUBSYSTEM, ELYTRON).add(ElytronDescriptionConstants.DYNAMIC_CLIENT_SSL_CONTEXT, DYNAMIC_SSL_CLIENT_CONTEXT_NAME);
        operation.get(ClientConstants.OP).set(ClientConstants.READ_RESOURCE_OPERATION);
        ModelNode result = assertSuccess(services.executeOperation(operation)).get(ClientConstants.RESULT);
        assertEquals("ac", result.get(ElytronDescriptionConstants.AUTHENTICATION_CONTEXT).asString());
    }
}
