package org.wildfly.test.security.common.elytron;

import org.jboss.as.test.integration.management.util.CLIWrapper;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.wildfly.core.testrunner.WildflyTestRunner;

import static org.hamcrest.core.StringContains.containsString;

@RunWith(WildflyTestRunner.class)
public class RegexRoleMapperTest {
    CLIWrapper cli;

    @Before
    public void setup() throws Exception {
        cli = new CLIWrapper(true);
        cli.sendLine("/subsystem=elytron/filesystem-realm=myFsRealm:add(path=my-fs-realm-users,relative-to=jboss.server.config.dir)");
        cli.sendLine("/subsystem=elytron/filesystem-realm=myFsRealm:add-identity(identity=john)");
        cli.sendLine("/subsystem=elytron/filesystem-realm=myFsRealm:add-identity-attribute(identity=john, name=Roles, value=[\"user\"])");
        cli.sendLine("/subsystem=elytron/security-domain=mySD:add(realms=[{realm=myFsRealm}],default-realm=myFsRealm,permission-mapper=default-permission-mapper)");
    }

    @AfterClass
    public void cleanup() throws Exception {
        removeTestResources();
        cli.close();
    }

    @Test
    public void testReadIdentityFromSecurityDomain() {
        boolean success = cli.sendLine("/subsystem=elytron/regex-role-mapper=rrm:add(pattern=\"guest\", replacement=\"\", keep-non-mapped=\"false\", replace-all=\"true\")", true);

        Assert.assertFalse(success);
        Assert.assertThat(cli.readOutput(), containsString("'' is an invalid value for parameter replacement. Values must have a minimum length of 1 characters\""));
    }

    @Test
    public void testReadIdentityFromSecurityDomain2() {
        boolean success = cli.sendLine("/subsystem=elytron/regex-role-mapper=rrm:add(pattern=\"guest\", replacement=\"\", keep-non-mapped=\"false\", replace-all=\"true\")", true);
        Assert.assertFalse(success);
        Assert.assertThat(cli.readOutput(), containsString("'' is an invalid value for parameter replacement. Values must have a minimum length of 1 characters\""));
    }

    private void removeTestResources() {
        cli.sendLine("/subsystem=elytron/security-domain=mySD:remove");
        cli.sendLine("/subsystem=elytron/filesystem-realm=myFsRealm:remove");
        cli.sendLine("reload");
    }
}
