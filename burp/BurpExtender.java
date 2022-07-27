package burp;

import java.io.PrintWriter;

public class BurpExtender implements IBurpExtender, IHttpListener {
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private PrintWriter debug;

    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.callbacks.setExtensionName("sample extension");

        this.callbacks.registerHttpListener(this);

        this.debug = new PrintWriter(callbacks.getStdout(), true);
        //this.debug.println("hello");
    }

    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo){
        if (messageIsRequest) {
            this.debug.println("Intercepted Request!");
        } else {
            this.debug.println("You entered incorrect input");
        }
    }
}
