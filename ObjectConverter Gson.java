
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

/**
 *
 * @author ctacon
 */
public class ObjectConverter {

    public static String getJsonFromObjectSimple(Object request) {
        Gson gson = new GsonBuilder().setPrettyPrinting().create();
        String json = gson.toJson(request);
        return json;
    }

    public static Object getObjectFromJsonSimple(Class someClass, String json) {
        Gson gson = new Gson();
        return gson.fromJson(json, someClass);
    }
}
