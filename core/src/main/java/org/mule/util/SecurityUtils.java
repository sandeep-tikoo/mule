/*
 * Copyright (c) MuleSoft, Inc.  All rights reserved.  http://www.mulesoft.com
 * The software in this package is published under the terms of the CPAL v1.0
 * license, a copy of which has been included with this distribution in the
 * LICENSE.txt file.
 */
package org.mule.util;


import org.mule.api.config.MuleProperties;
import org.mule.api.security.tls.TlsConfiguration;

import java.lang.reflect.Constructor;
import java.security.Provider;
import java.security.Security;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

public final class SecurityUtils
{
    /**
     * logger used by this class
     */
    protected static final Log logger = LogFactory.getLog(SecurityUtils.class);

    private static final String PREFERED_PROVIDER_NAME = "BC";

    public static String getSecurityModel()
    {
        return System.getProperty(MuleProperties.MULE_SECURITY_SYSTEM_PROPERTY, TlsConfiguration.DEFAULT_SECURITY_MODEL);
    }

    public static boolean isFipsSecurityModel()
    {
        return getSecurityModel().equals(TlsConfiguration.FIPS_SECURITY_MODEL);
    }

    public static boolean isDefaultSecurityModel()
    {
        return getSecurityModel().equals(TlsConfiguration.DEFAULT_SECURITY_MODEL);
    }

    /**
     * Registers the Mule Security Provider with the highest priority.
     * This is needed if the security provider given by a system property
     * must be used by third party libraries.
     * <p>
     *     <b>Note:</b> Use this method as a last resort for cases were a library always requires you to
     *     override the JCE priority because of a bug in the JDK. 
     * </p>
     */
    public static void registerMuleSecurityProviderAsDefault()
    {
        String providerName = System.getProperty(MuleProperties.MULE_SECURITY_PROVIDER_PROPERTY);        
        try
        {
            if (providerName != null && !Security.getProviders()[0].getName().equals(providerName))
            {
                Class<?> providerClass = Class.forName(providerName);
                Constructor<?> constructor = providerClass.getConstructors()[0];
                Provider provider = (Provider) constructor.newInstance();
                Security.removeProvider(provider.getName());
                Security.insertProviderAt(provider, 1);
            }
        } catch (Exception e) {
            logger.warn("Error registering security provider ", e);
        }
    }
    
    /**
     * Returns the default security provider that should be used in scenarios where ONE provider must be
     * explicitly given. It will get the first registered provider in order of preference, unless a
     * system variable is defined with a provider name.
     *
     * <p>
     *     <b>Note:</b> Use this method as a last resort for cases were a library always requires you to
     *     provide one. JCE already provides an excellent provider selection algorithm, and many operations
     *     will automatically choose the best provider if you don't force one in particular
     * </p>
     */
    public static Provider getDefaultSecurityProvider()
    {
        String providerName = System.getProperty(MuleProperties.MULE_SECURITY_PROVIDER_PROPERTY);
        Provider provider = null;
        if (providerName == null)
        {
            if (!isFipsSecurityModel())
            {
                provider = Security.getProvider(PREFERED_PROVIDER_NAME);
            }
            if (provider == null)
            {
                Provider[] providers = Security.getProviders();
                if (providers.length > 0)
                {
                    provider = providers[0];
                }
            }
        }
        else
        {
            provider =  Security.getProvider(providerName);
        }

        if (provider == null)
        {
            throw new IllegalStateException("Can't find a suitable security provider. " + (providerName == null ? "" : "Provider name " + providerName + " was not found."));
        }
        return provider;
    }
}
