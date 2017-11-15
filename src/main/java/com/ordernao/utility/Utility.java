package com.ordernao.utility;

import java.util.Arrays;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class Utility {
	static final Logger logger = LogManager.getLogger(Utility.class.getName());

	public static String[] getArrayFromString(String string) {
		logger.info("String :- " + string);
		String inputString = string.substring(1, string.length() - 1);
		logger.info("String(after removing []) :- " + inputString);
		String[] stringArray = inputString.split("&#@");
		int arrayLength = stringArray.length;
		logger.info("String length (after splitting with &#@) :- " + arrayLength);
		for (int i = 0; i < arrayLength; i++) {
			String input = stringArray[i];
			logger.info("Input String :-" + stringArray[i]);
			stringArray[i] = input.replaceAll("[\\\",]", "");
			logger.info("Output String :-" + stringArray[i]);
		}
		String[] newArray = Arrays.copyOf(stringArray, (stringArray.length - 1));
		logger.info("String length (after splitting with &#@) :- " + newArray.length);
		for (int i = 0; i < newArray.length; i++) {
			logger.info("new String:- " + newArray[i]);
		}
		return newArray;
	}

}
