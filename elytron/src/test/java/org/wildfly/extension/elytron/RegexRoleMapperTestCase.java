/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2019 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wildfly.extension.elytron;

import org.jboss.as.controller.client.helpers.ClientConstants;
import org.jboss.as.subsystem.test.AbstractSubsystemBaseTest;
import org.jboss.as.subsystem.test.KernelServices;
import org.jboss.dmr.ModelNode;
import org.jboss.msc.service.ServiceName;
import org.junit.Assert;
import org.junit.Test;
import org.wildfly.security.auth.server.SecurityDomain;
import org.wildfly.security.auth.server.SecurityIdentity;
import org.wildfly.security.auth.server.ServerAuthenticationContext;
import org.wildfly.security.authz.Roles;

import java.io.IOException;

import static org.jboss.as.controller.descriptions.ModelDescriptionConstants.FAILED;
import static org.jboss.as.controller.descriptions.ModelDescriptionConstants.OUTCOME;

public class RegexRoleMapperTestCase extends AbstractSubsystemBaseTest {
    private KernelServices services = null;

    public RegexRoleMapperTestCase() {
        super(ElytronExtension.SUBSYSTEM_NAME, new ElytronExtension());
    }

    @Override
    protected String getSubsystemXml() throws IOException {
        return readResource("role-mappers-test.xml");
    }

    private void init(String... domainsToActivate) throws Exception {
        services = super.createKernelServicesBuilder(new TestEnvironment()).setSubsystemXmlResource("role-mappers-test.xml").build();
        if (!services.isSuccessfulBoot()) {
            Assert.fail(services.getBootError().toString());
        }
        TestEnvironment.activateService(services, Capabilities.SECURITY_DOMAIN_RUNTIME_CAPABILITY, "TestDomain5");
        TestEnvironment.activateService(services, Capabilities.SECURITY_DOMAIN_RUNTIME_CAPABILITY, "TestDomain6");
        TestEnvironment.activateService(services, Capabilities.SECURITY_DOMAIN_RUNTIME_CAPABILITY, "TestDomain7");
        TestEnvironment.activateService(services, Capabilities.SECURITY_DOMAIN_RUNTIME_CAPABILITY, "TestDomain8");
    }

    @Test
    public void testRegexRoleMapper() throws Exception {
        init("TestDomain5");

        ServiceName serviceName = Capabilities.SECURITY_DOMAIN_RUNTIME_CAPABILITY.getCapabilityServiceName("TestDomain5");
        Assert.assertNotNull(services.getContainer());
        Assert.assertNotNull(services.getContainer().getService(serviceName));
        SecurityDomain domain = (SecurityDomain) services.getContainer().getService(serviceName).getValue();
        Assert.assertNotNull(domain);

        ServerAuthenticationContext context = domain.createNewAuthenticationContext();
        context.setAuthenticationName("user2");
        Assert.assertTrue(context.exists());
        Assert.assertTrue(context.authorize());
        context.succeed();
        SecurityIdentity identity = context.getAuthorizedIdentity();

        Roles roles = identity.getRoles();
        Assert.assertTrue(roles.contains("application-user"));
        Assert.assertFalse(roles.contains("123-user"));
        Assert.assertFalse(roles.contains("joe"));
        Assert.assertEquals("user2", identity.getPrincipal().getName());
    }

    @Test
    public void testRegexRoleMapper2() throws Exception {
        init("TestDomain6");

        ServiceName serviceName = Capabilities.SECURITY_DOMAIN_RUNTIME_CAPABILITY.getCapabilityServiceName("TestDomain6");
        Assert.assertNotNull(services.getContainer());
        Assert.assertNotNull(services.getContainer().getService(serviceName));
        SecurityDomain domain = (SecurityDomain) services.getContainer().getService(serviceName).getValue();
        Assert.assertNotNull(domain);

        ServerAuthenticationContext context = domain.createNewAuthenticationContext();
        context.setAuthenticationName("user3");
        Assert.assertTrue(context.exists());
        Assert.assertTrue(context.authorize());
        context.succeed();
        SecurityIdentity identity = context.getAuthorizedIdentity();

        Roles roles = identity.getRoles();
        Assert.assertTrue(roles.contains("admin"));
        Assert.assertTrue(roles.contains("user"));
        Assert.assertFalse(roles.contains("joe"));
        Assert.assertFalse(roles.contains("application-user"));
        Assert.assertFalse(roles.contains("123-admin-123"));
        Assert.assertFalse(roles.contains("aa-user-aa"));
        Assert.assertEquals("user3", identity.getPrincipal().getName());
    }

    @Test
    public void testRegexRoleMapper3() throws Exception {
        init("TestDomain7");

        ServiceName serviceName = Capabilities.SECURITY_DOMAIN_RUNTIME_CAPABILITY.getCapabilityServiceName("TestDomain7");
        Assert.assertNotNull(services.getContainer());
        Assert.assertNotNull(services.getContainer().getService(serviceName));
        SecurityDomain domain = (SecurityDomain) services.getContainer().getService(serviceName).getValue();
        Assert.assertNotNull(domain);

        ServerAuthenticationContext context = domain.createNewAuthenticationContext();
        context.setAuthenticationName("user3");
        Assert.assertTrue(context.exists());
        Assert.assertTrue(context.authorize());
        context.succeed();
        SecurityIdentity identity = context.getAuthorizedIdentity();

        Roles roles = identity.getRoles();
        Assert.assertTrue(roles.contains("admin"));
        Assert.assertTrue(roles.contains("user"));
        Assert.assertTrue(roles.contains("joe"));
        Assert.assertFalse(roles.contains("application-user"));
        Assert.assertFalse(roles.contains("123-admin-123"));
        Assert.assertFalse(roles.contains("aa-user-aa"));
        Assert.assertEquals("user3", identity.getPrincipal().getName());
    }

    @Test
    public void testAddRegexRoleMapperWillFailWithInvalidRegexAttribute() throws Exception {
        init();
        ModelNode operation = new ModelNode();
        operation.get(ClientConstants.OP_ADDR).add("subsystem", "elytron").add("regex-role-mapper", "my-regex-role-mapper");
        operation.get(ClientConstants.OP).set(ClientConstants.ADD);
        operation.get(ElytronDescriptionConstants.PATTERN).set("*-admin");
        operation.get(ElytronDescriptionConstants.REPLACEMENT).set("$1");
        ModelNode response = services.executeOperation(operation);
        // operation will fail because regex is not valid (starts with asterisk)
        if (! response.get(OUTCOME).asString().equals(FAILED)) {
            Assert.fail(response.toJSONString(false));
        }
    }

    @Test
    public void testAddRegexRoleMapperReplaceAll() throws Exception {
        init("TestDomain8");

        ServiceName serviceName = Capabilities.SECURITY_DOMAIN_RUNTIME_CAPABILITY.getCapabilityServiceName("TestDomain8");
        Assert.assertNotNull(services.getContainer());
        Assert.assertNotNull(services.getContainer().getService(serviceName));
        SecurityDomain domain = (SecurityDomain) services.getContainer().getService(serviceName).getValue();
        Assert.assertNotNull(domain);

        ServerAuthenticationContext context = domain.createNewAuthenticationContext();
        context.setAuthenticationName("user4");
        Assert.assertTrue(context.exists());
        Assert.assertTrue(context.authorize());
        context.succeed();
        SecurityIdentity identity = context.getAuthorizedIdentity();

        Roles roles = identity.getRoles();
        Assert.assertTrue(roles.contains("app-user"));
        Assert.assertTrue(roles.contains("app-user-first-time-user"));
        Assert.assertFalse(roles.contains("app-guest"));
        Assert.assertFalse(roles.contains("app-guest-first-time-guest"));
        Assert.assertFalse(roles.contains("app-user-first-time-guest"));
        Assert.assertFalse(roles.contains("app-guest-first-time-user"));
        Assert.assertFalse(roles.contains("joe"));
        Assert.assertEquals("user4", identity.getPrincipal().getName());
    }
}
