package sms;

import java.util.Map;

public class SmsServiceFactory {

    public static SmsService get(Map<String, String> config) {
        if (Boolean.parseBoolean(config.getOrDefault("simulation", "false"))) {
            return ((phoneNumber, message) ->
                    System.out.printf("***** TEST MODE *****\n Would send SMS to %s with text: %s%n", phoneNumber, message));
        } else {
            return new SmsServiceImpl(config.get("accessKey"), config.get("originator"));
        }
    }

}
