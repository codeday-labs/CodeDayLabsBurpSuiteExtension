package burp;

import javax.swing.*;
import java.awt.*;
import java.io.PrintWriter;

public class BurpExtender implements IBurpExtender, IHttpListener, ITab {
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private PrintWriter debug;
    private JSplitPane splitPane;

    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.callbacks.setExtensionName("sample extension");

        this.callbacks.registerHttpListener(this);

        SwingUtilities.invokeLater(new Runnable() {

            @Override
            public void run() {
                splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);

                callbacks.customizeUiComponent(splitPane);
                callbacks.addSuiteTab(BurpExtender.this);
            }
        });

        this.debug = new PrintWriter(callbacks.getStdout(), true);
        //this.debug.println("hello");
    }

    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo){
        if (messageIsRequest) {
            this.debug.println("Intercepted Request!");
        } else {
            this.debug.println("Intercepted Response");
        }
    }

    @Override
    public String getTabCaption() {
        return "Test";
    }

    @Override
    public Component getUiComponent() {
        return splitPane;
    }
}

