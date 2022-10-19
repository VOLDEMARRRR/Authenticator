package sms;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;


public class SmsServiceImpl implements SmsService{

    public SmsServiceImpl(String accessKey, String originator) {}

    @Override
    public void send(String phoneNumber, String message) throws IOException {

        String urlMessage = URLEncoder.encode(message, String.valueOf(StandardCharsets.UTF_8));
        String url = String.format("https://sms.ru/sms/send?api_id=DDCE175D-C8E0-CB54-55B8-373DC56D4950&to={%s}&msg={%s}&json=1", phoneNumber, urlMessage);
        URL obj = new URL(url);
        HttpURLConnection connection = (HttpURLConnection) obj.openConnection();
        connection.getInputStream();
    }

}
