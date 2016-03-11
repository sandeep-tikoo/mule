/*
 * Copyright (c) MuleSoft, Inc.  All rights reserved.  http://www.mulesoft.com
 * The software in this package is published under the terms of the CPAL v1.0
 * license, a copy of which has been included with this distribution in the
 * LICENSE.txt file.
 */
package org.mule.module.extension.internal;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.when;
import static org.mule.module.extension.HeisenbergExtension.HEISENBERG;
import org.mule.extension.api.ExtensionManager;
import org.mule.extension.api.introspection.RuntimeConfigurationModel;
import org.mule.extension.api.introspection.RuntimeExtensionModel;
import org.mule.extension.api.runtime.ConfigurationProvider;
import org.mule.functional.junit4.ExtensionFunctionalTestCase;

import org.hamcrest.core.IsInstanceOf;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;

@RunWith(MockitoJUnitRunner.class)
public class HeisenbergDefaultConfigTestCase extends ExtensionFunctionalTestCase
{

    @Rule
    public ExpectedException expectedException = ExpectedException.none();

    @Mock
    private RuntimeConfigurationModel configurationModel;

    @Mock
    private ConfigurationProvider<Object> configurationProvider;

    @Override
    protected String getConfigFile()
    {
        return "heisenberg-default-config.xml";
    }

    @Test
    public void usesDefaultConfig() throws Exception
    {
        assertThat(getPayloadAsString(runFlow("sayMyName").getMessage()), is("Heisenberg"));
    }

    @Test
    public void twoConfigsAndNoConfigRef() throws Exception
    {
        ExtensionManager extensionManager = muleContext.getExtensionManager();
        RuntimeExtensionModel extensionModel = extensionManager.getExtensions().stream().findFirst().get();
        assertThat(extensionModel.getName(), is(HEISENBERG));

        when(configurationProvider.getName()).thenReturn("secondConfig");
        when(configurationProvider.getModel()).thenReturn(configurationModel);
        when(configurationModel.getExtensionModel()).thenReturn(extensionModel);

        extensionManager.registerConfigurationProvider(configurationProvider);

        expectedException.expectCause(IsInstanceOf.<IllegalStateException>instanceOf(IllegalStateException.class));
        runFlow("sayMyName");
    }
}