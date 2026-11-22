package com.innernetwork.crm.tenancy;

import javax.sql.DataSource;

import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration(proxyBeanMethods = false)
class TenancyConfig {

	/** Wraps the app's connection pool so every connection carries the current tenant. */
	@Bean
	static BeanPostProcessor tenantAwareDataSourcePostProcessor() {
		return new BeanPostProcessor() {
			@Override
			public Object postProcessAfterInitialization(Object bean, String beanName) {
				if (bean instanceof DataSource dataSource && !(bean instanceof TenantAwareDataSource)) {
					return new TenantAwareDataSource(dataSource);
				}
				return bean;
			}
		};
	}

}
