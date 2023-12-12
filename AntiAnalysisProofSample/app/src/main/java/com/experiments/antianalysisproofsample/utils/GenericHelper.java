package com.experiments.antianalysisproofsample.utils;

import java.util.Collection;

public class GenericHelper {
    public static String[] convertCollectionToArray(Collection<String> setOfString) {

        // Create String[] of size of setOfString
        String[] arrayOfString = new String[setOfString.size()];

        // Copy elements from set to string array
        // using advanced for loop
        int index = 0;
        for (String str : setOfString)
            arrayOfString[index++] = str;

        // return the formed String[]
        return arrayOfString;
    }

    public static int rotateLeft(int i, int distance) {
        return (i << distance) | (i >>> -distance);
    }
}
