package com.ordernao.properties;

import java.util.Map;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.PropertySource;
import org.springframework.stereotype.Component;

@Component
@EnableConfigurationProperties
@ConfigurationProperties
@PropertySource("classpath:./queries.properties")
public class QueriesProperty {
	private Map<String, String> query;

	public Map<String, String> getQuery() {
		return query;
	}

	public void setQuery(Map<String, String> query) {
		this.query = query;
	}
	public String getProperty(String propertyName){
		return query.get(propertyName);
	}

}
