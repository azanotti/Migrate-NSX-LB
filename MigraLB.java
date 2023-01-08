//Author: Alessandro Zanotti	Date: 18/12/2021
import org.json.*;
import java.util.Scanner;
import java.io.*;
import java.net.*;
import java.util.Base64;
import java.nio.file.Files;
import java.nio.file.Path;
import java.net.http.*;
import java.net.http.HttpRequest.BodyPublishers;
import java.net.URI;
import java.net.http.HttpResponse.BodyHandlers;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.security.cert.X509Certificate;


public class MigraLB{
    //Dichiarazione variabili universali
    public static String nsxvurl;
    public static String nsxvuser;
    public static String nsxvpwd;
    public static String nsxturl;
    public static String nsxtuser;
    public static String nsxtpwd;

    public static boolean isReachable(String targetUrl) throws IOException, Exception{
        TrustManager[] trustAllCerts = new TrustManager[] { new X509TrustManager() {
            public java.security.cert.X509Certificate[] getAcceptedIssuers() {
              return null;
            }
      
            public void checkClientTrusted(X509Certificate[] certs, String authType) {
            }
      
            public void checkServerTrusted(X509Certificate[] certs, String authType) {
            }
        }};
      
        SSLContext sc = SSLContext.getInstance("SSL");
        sc.init(null, trustAllCerts, new java.security.SecureRandom());
        HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());

        HttpURLConnection httpUrlConnection = (HttpURLConnection) new URL(targetUrl).openConnection();
        httpUrlConnection.setRequestMethod("HEAD");
        boolean stat = false;
        try{
            int responseCode = httpUrlConnection.getResponseCode();
            if(responseCode == 200 || responseCode == 401){
                stat = true;
            }
        } catch (UnknownHostException noInternetConnection){
            stat = false;
            return false;
        }
        return stat;
    }
    public static void inviaJSON(String jsonIN) throws IOException, Exception {
        TrustManager[] trustAllCerts = new TrustManager[] { new X509TrustManager() {
            public java.security.cert.X509Certificate[] getAcceptedIssuers() {
              return null;
            }
      
            public void checkClientTrusted(X509Certificate[] certs, String authType) {
            }
      
            public void checkServerTrusted(X509Certificate[] certs, String authType) {
            }
        }};
        SSLContext sc = SSLContext.getInstance("SSL");
        sc.init(null, trustAllCerts, new java.security.SecureRandom());

        boolean status = isReachable(nsxturl);
        if(status == true){
            try{
                String userCredentials = nsxtuser + ":" + nsxtpwd;
                String basicAuth = "Basic " + new String(Base64.getEncoder().encode(userCredentials.getBytes()));
                HttpClient client = HttpClient.newBuilder().sslContext(sc).build();
                HttpRequest request = HttpRequest.newBuilder().uri(URI.create(nsxturl+"/policy/api/v1/infra/")).method("PATCH", BodyPublishers.ofString(jsonIN)).header("Content-Type", "application/json").header("Authorization", basicAuth).build();
                HttpResponse response = client.sendAsync(request, BodyHandlers.ofString()).join();
                System.out.println("Codice di risposta da NSX-T: " + response.statusCode());
                if(response.statusCode() != 200){
                    System.out.println(response.body());
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        } else {
            System.out.println("L'URL inserito non risulta raggiungibile sulla porta 443");
        }
    }
    public static String riceviJSON(int edgeID) throws IOException, Exception{
        TrustManager[] trustAllCerts = new TrustManager[] { new X509TrustManager() {
            public java.security.cert.X509Certificate[] getAcceptedIssuers() {
              return null;
            }
      
            public void checkClientTrusted(X509Certificate[] certs, String authType) {
            }
      
            public void checkServerTrusted(X509Certificate[] certs, String authType) {
            }
        }};
      
        SSLContext sc = SSLContext.getInstance("SSL");
        sc.init(null, trustAllCerts, new java.security.SecureRandom());
        HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());

        String output = "";
        boolean status = isReachable(nsxvurl);
        if(status == true){
            try {
                URL url = new URL(nsxvurl + "/api/4.0/edges/edge-"+edgeID+"/loadbalancer/config");
                
                String userCredentials = nsxvuser + ":" + nsxvpwd;
                String basicAuth = "Basic " + new String(Base64.getEncoder().encode(userCredentials.getBytes()));
    
                HttpURLConnection connection = (HttpURLConnection) url.openConnection();
                connection.setRequestMethod("GET");
                connection.setDoOutput(true);
                connection.setRequestProperty("Authorization", basicAuth);
            
                InputStream content = (InputStream) connection.getInputStream();
                BufferedReader in = new BufferedReader(new InputStreamReader(content));
                StringBuilder sb = new StringBuilder();
                String line;
                while ((line = in.readLine()) != null) {
                    sb.append(line).append("\n");
                }
                output = sb.toString();
            } catch (Exception e) {
                e.printStackTrace();
            }
        } else {
            System.out.println("L'URL inserito non risulta raggiungibile sulla porta 443");
        }
        return output;
    }
    public static void main(String[] args) throws IOException, Exception {
        Scanner tastiera = new Scanner(System.in);
        Console console = System.console();

        System.out.print("Inserisci l'url di NSX-V (formato https://nsx-v-fqdn): ");
        nsxvurl = tastiera.next();
        System.out.print("Inserisci il nome utente: ");
        nsxvuser = tastiera.next();
        if(console != null){
            char[] ch = console.readPassword("Inserisci la password: ");
            nsxvpwd = String.valueOf(ch);
        }
        System.out.print("Inserisci l'url di NSX-T (formato https://nsx-t-fqdn): ");
        nsxturl = tastiera.next();
        System.out.print("Inserisci il nome utente: ");
        nsxtuser = tastiera.next();
        if(console != null){
            char[] ch = console.readPassword("Inserisci la password: ");
            nsxtpwd = String.valueOf(ch);
        }

        //Inserimento id edge da appendere
        System.out.print("Inserisci l'id dell'edge da migrare: ");
        int edgeId = tastiera.nextInt();

        //Caricamento del file XML come stringa e conversione in JSON object
        String xmlString = riceviJSON(edgeId);
        JSONObject toor = XML.toJSONObject(xmlString);

        //Creazione del sistema JSON di output
        JSONObject root = new JSONObject();
        root.put("resource_type", "Infra");
        JSONArray child = new JSONArray();

        //Apro il load balancer in JSON
        JSONObject LBElement = toor.getJSONObject("loadBalancer");
        boolean enabled = (Boolean) LBElement.get("enabled");

        //Controllo se il load balancer era abilitato (in caso termino l'esecuzione)
        if(enabled == false){
            System.out.println("Il load balancer importato era disabilitato");
            System.exit(1);
        }

        //Controllo se sono array o elementi
        JSONArray vsArray = new JSONArray();
        JSONArray appArray = new JSONArray();
        JSONArray monArray = new JSONArray();
        JSONArray poolArray = new JSONArray();


        Object vsItem = LBElement.get("virtualServer"); 
        if (vsItem instanceof JSONArray){
            vsArray = (JSONArray) vsItem;
        } else {
            vsArray.put(vsItem);
        }
        Object appItem = LBElement.get("applicationProfile"); 
        if (appItem instanceof JSONArray){
            appArray = (JSONArray) appItem;
        } else {
            appArray.put(appItem);
        }
        Object monItem = LBElement.get("monitor"); 
        if (monItem instanceof JSONArray){
            monArray = (JSONArray) monItem;
        } else {
            monArray.put(monItem);
        }
        Object poolItem = LBElement.get("pool"); 
        if (poolItem instanceof JSONArray){
            poolArray = (JSONArray) poolItem;
        } else {
            poolArray.put(poolItem);
        }

        //Processo i dati ottenuti
        for(int i = 0; i < vsArray.length(); i++){
            JSONObject temp = vsArray.getJSONObject(i);
            String name = temp.getString("name");
            boolean ena = (Boolean) temp.get("enabled");
            String ip = temp.getString("ipAddress");
            String protocol = temp.getString("protocol");
            int port = (int) temp.get("port");
            int connLimit = (int) temp.get("connectionLimit");
            String applicationProfileId = temp.getString("applicationProfileId");
            String poolId = temp.getString("defaultPoolId");  

            //Ricerca id JSON dell'application profile
            int appNumber = -1;
            for(int j = 0; j < appArray.length(); j++){
                JSONObject tempapp = appArray.getJSONObject(j);
                String appProfileId = tempapp.getString("applicationProfileId");
                if(appProfileId.equalsIgnoreCase(applicationProfileId)){
                    appNumber = j;
                }
            }

            //Lettura dell'application profile
            JSONObject currentAppProfile = appArray.getJSONObject(appNumber);
            String appProfileId = currentAppProfile.getString("applicationProfileId");
            String appName = currentAppProfile.getString("name");
            boolean xForwarded = (boolean) currentAppProfile.get("insertXForwardedFor");
            boolean sslPassthrough = (boolean) currentAppProfile.get("sslPassthrough");
            String perMethod = "empty";
            if(currentAppProfile.has("persistence")){
                JSONObject persistence = currentAppProfile.getJSONObject("persistence");
                perMethod = persistence.getString("method");
            }

            //Ricerca id JSON della pool
            int poolNumber = -1;
            for(int j = 0; j < poolArray.length(); j++){
                JSONObject tempPool = poolArray.getJSONObject(j);
                String tempPoolId = tempPool.getString("poolId");
                if(tempPoolId.equalsIgnoreCase(poolId)){
                    poolNumber = j;
                }
            }

            //Lettura della pool
            JSONObject currentPool = poolArray.getJSONObject(poolNumber);
            String poolName = currentPool.getString("name");
            String algorithm = currentPool.getString("algorithm");
            boolean transparent = (boolean) currentPool.get("transparent");
            String monitorId = "empty";
            if(currentPool.has("monitorId")){
                monitorId = currentPool.getString("monitorId");
            }
            JSONArray members = new JSONArray();
            Object memberItem = currentPool.get("member"); 
            if (memberItem instanceof JSONArray){
                members = (JSONArray) memberItem;
            } else {
                members.put(memberItem);
            }
            JSONArray memOut = new JSONArray();
            int monPortOut = 0;
            for(int j = 0; j < members.length(); j++){
                JSONObject tempMember = members.getJSONObject(j);
                String memIP = tempMember.getString("ipAddress");
                int memWeight = (int) tempMember.get("weight");
                int memPort = (int) tempMember.get("port");
                String memName = tempMember.getString("name");
                if(monPortOut == 0){
                    if(tempMember.has("monitorPort")){
                        monPortOut = (int) tempMember.get("monitorPort");
                    }
                }
                JSONObject tempOut = new JSONObject();
                tempOut.put("admin_state","ENABLED");
                tempOut.put("backup_member","false");
                tempOut.put("display_name", memName);
                tempOut.put("ip_address", memIP);
                tempOut.put("max_concurrent_connections","1");
                tempOut.put("port", String.valueOf(memPort));
                tempOut.put("weight", String.valueOf(memWeight));
                memOut.put(tempOut);
            }

            //Ricerca id JSON del monitor profile
            int monNumber = -1;
            String monitorName = "empty";
            if(!monitorId.equalsIgnoreCase("empty")){
                for(int j = 0; j < monArray.length(); j++){
                    JSONObject tempMon = monArray.getJSONObject(j);
                    String tempMonId = tempMon.getString("monitorId");
                    if(tempMonId.equalsIgnoreCase(monitorId)){
                        monNumber = j;
                    }
                }
                //Lettura del monitor profile
                JSONObject currentMonitor = monArray.getJSONObject(monNumber);
                String monName = currentMonitor.getString("name");
                String monType = currentMonitor.getString("type");
                int monInterval = (int) currentMonitor.get("interval");
                int monTimeout = (int) currentMonitor.get("timeout");
                int monRetries = (int) currentMonitor.get("maxRetries");
                String method = "empty";
                String url = "empty";
                String expected = "empty";
                String send = "empty";
                String receive = "empty";
                if(!monType.equalsIgnoreCase("tcp")){
                    if(currentMonitor.has("method")){
                        method = currentMonitor.getString("method");
                    }
                    if(currentMonitor.has("url")){
                        url = currentMonitor.getString("url");
                    }
                    if(currentMonitor.has("expected")){
                        expected = currentMonitor.getString("expected");
                    }
                    if(currentMonitor.has("send")){
                        send = currentMonitor.getString("send");
                    }
                    if(currentMonitor.has("receive")){
                        receive = currentMonitor.getString("receive");
                    }
                }
                //Output dei monitor profile
                monitorName = monName+"_"+edgeId;
                JSONObject monOut = new JSONObject();
                String monTypeNSXT = "";
                monType = monType.toLowerCase();
                switch(monType){
                    case "http": monTypeNSXT = "LBHttpMonitorProfile"; break;
                    case "https": monTypeNSXT = "LBHttpsMonitorProfile"; break;
                    case "icmp": monTypeNSXT = "LBIcmpMonitorProfile"; break;
                    case "tcp": monTypeNSXT = "LBTcpMonitorProfile"; break;
                    case "udp": monTypeNSXT = "LBUdpMonitorProfile"; break;
                }
                monOut.put("resource_type","ChildLBMonitorProfile");
                monOut.put("marked_for_delete", "false");
                JSONObject LBMonitorProfile = new JSONObject();
                LBMonitorProfile.put("resource_type", monTypeNSXT);
                LBMonitorProfile.put("marked_for_delete", "false");
                LBMonitorProfile.put("id", monitorName);
                LBMonitorProfile.put("interval", String.valueOf(monInterval));
                LBMonitorProfile.put("fall_count", String.valueOf(monRetries));
                if(monPortOut != 0){
                    LBMonitorProfile.put("monitor_port", String.valueOf(monPortOut));
                }
                if(monType.equalsIgnoreCase("http") || monType.equalsIgnoreCase("https")){
                    if(!method.equalsIgnoreCase("empty")){
                        LBMonitorProfile.put("request_method", method);
                    }
                    if(!url.equalsIgnoreCase("empty")){
                        LBMonitorProfile.put("request_url", url);
                    }
                    if(!expected.equalsIgnoreCase("empty")){
                        LBMonitorProfile.put("request_version", "HTTP_VERSION_1_1");
                    }
                    if(!send.equalsIgnoreCase("empty")){
                        LBMonitorProfile.put("request_body", send);
                    }
                    if(!receive.equalsIgnoreCase("empty")){
                        LBMonitorProfile.put("response_body", receive);
                    }
                }
                monOut.put("LBMonitorProfile", LBMonitorProfile);
                child.put(monOut);
            }

            //Output degli application profile
            String appProfileName = appName+"_"+edgeId;
            String appTypeNSXT = "";
            protocol = protocol.toLowerCase();
            switch(protocol){
                case "http": appTypeNSXT = "LBHttpProfile"; break;
                case "https": appTypeNSXT = "LBHttpProfile"; break;
                case "tcp": appTypeNSXT = "LBFastTcpProfile"; break;
                case "udp": appTypeNSXT = "LBFastUdpProfile"; break;
                default: System.out.println("Protocollo del Virtual Server non valido"); System.exit(1);
            }
            JSONObject appOut = new JSONObject();
            appOut.put("resource_type","ChildLBAppProfile");
            appOut.put("marked_for_delete", "false");
            JSONObject LBApplicationProfile = new JSONObject();
            LBApplicationProfile.put("resource_type", appTypeNSXT);
            LBApplicationProfile.put("marked_for_delete", "false");
            LBApplicationProfile.put("id", appProfileName);
            if(xForwarded == true){
                LBApplicationProfile.put("x_forwarded_for", "INSERT");
            }
            appOut.put("LBAppProfile", LBApplicationProfile);
            child.put(appOut);

            //Output delle pool
            String poolNameOut = poolName + "_" + edgeId;
            String algorithmNSXT = "";
            algorithm = algorithm.toLowerCase();
            switch(algorithm){
                case "round-robin": algorithmNSXT = "ROUND_ROBIN"; break;
                case "ip-hash": algorithmNSXT = "IP_HASH"; break;
                case "leastconn": algorithmNSXT = "LEAST_CONNECTION"; break;
                default: System.out.println("Ho modificato l'algoritmo della pool " + poolNameOut + " da " + algorithm + " a ROUND_ROBIN"); algorithmNSXT = "ROUND_ROBIN"; break;
            }
            JSONObject poolOut = new JSONObject();
            poolOut.put("resource_type","ChildLBPool");
            poolOut.put("marked_for_delete", "false");
            JSONObject LBPoolOut = new JSONObject();
            LBPoolOut.put("id", poolNameOut);
            LBPoolOut.put("resource_type", "LBPool");
            LBPoolOut.put("marked_for_delete", "false");
            LBPoolOut.put("algorithm", algorithmNSXT);
            if(!monitorName.equalsIgnoreCase("empty")){
                JSONArray active_monitor_paths = new JSONArray();
                active_monitor_paths.put("/infra/lb-monitor-profiles/" + monitorName);
                LBPoolOut.put("active_monitor_paths",active_monitor_paths);
            }
            String SnatType = "";
            if(transparent == true){
                SnatType = "LBSnatDisabled";
            } else {
                SnatType = "LBSnatAutoMap";
            }
            JSONObject snat_translation = new JSONObject();
            snat_translation.put("type", SnatType);
            LBPoolOut.put("snat_translation", snat_translation);
            LBPoolOut.put("members", memOut);
            poolOut.put("LBPool", LBPoolOut);
            child.put(poolOut);

            //Output dei virtual server
            String perMethodNSXT = "empty";
            if(!perMethod.equalsIgnoreCase("empty")){
                perMethod = perMethod.toLowerCase();
                switch(perMethod){
                    case "cookie": perMethodNSXT = "default-cookie-lb-persistence-profile"; break;
                    case "sourceip": perMethodNSXT = "default-source-ip-lb-persistence-profile"; break;
                    default: System.out.println("Ho modificato il persistence profile di " + name + "_" + edgeId + " da " + perMethod + " a sourceIp"); perMethodNSXT = "default-source-ip-lb-persistence-profile"; break;
                }
            }
            JSONObject vsOut = new JSONObject();
            String vsName = name + "_" + edgeId;
            vsOut.put("resource_type","ChildLBVirtualServer");
            vsOut.put("marked_for_delete", "false");
            JSONObject LBVirtualServer = new JSONObject();
            LBVirtualServer.put("resource_type","LBVirtualServer");
            LBVirtualServer.put("id", vsName);
            LBVirtualServer.put("ip_address", ip);
            JSONArray LBPorts = new JSONArray();
            LBPorts.put(String.valueOf(port));
            LBVirtualServer.put("ports", LBPorts);
            LBVirtualServer.put("pool_path", "/infra/lb-pools/"+poolNameOut);
            LBVirtualServer.put("application_profile_path", "/infra/lb-app-profiles/" + appProfileName);
            if(!perMethodNSXT.equalsIgnoreCase("empty")){
                LBVirtualServer.put("lb_persistence_profile_path", "/infra/lb-persistence-profiles/" + perMethodNSXT);
            }
            vsOut.put("LBVirtualServer", LBVirtualServer);
            child.put(vsOut);
        }
        root.put("children", child);
        FileWriter jsonout = new FileWriter("edge_" + edgeId + ".json");
        jsonout.write(root.toString(4));
        jsonout.close();
        System.out.println("Ho convertito in " + "edge_" + edgeId + ".json");
        inviaJSON(root.toString(4));
        tastiera.close();
    }
}