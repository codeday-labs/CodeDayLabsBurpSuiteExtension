// Debug using java -agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=*:5005 -jar burpsuite_community.jar
package burp;
import org.jetbrains.annotations.NotNull;

import java.awt.Component;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import javax.swing.*;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableModel;

//public class BurpExtender extends AbstractTableModel implements IBurpExtender, IHttpListener, ITab, IMessageEditorController {
public class BurpExtender implements IBurpExtender, IHttpListener, ITab, IMessageEditorController {
    private IHttpRequestResponse currentlyDisplayedItem;
    private String[] apiName = {"API Path"};
    private String[] httpName = {"HTTP Response"};
    private DefaultTableModel apiTableModel = new DefaultTableModel(apiName, 0);
    private DefaultTableModel httpTableModel = new DefaultTableModel(httpName, 0);

    private final JTable apiResponseJTable = new JTable(apiTableModel)
    {
        public boolean isCellEditable(int row, int column) {
            return false;
        }
        @Override
        public Object getValueAt(int row, int column) {
            try {
                if(apiTableModel.getRowCount() > 0){ setSelectedData();}
            }
            catch(Exception e){
                return super.getValueAt(row, column);
            }
            return super.getValueAt(row, column);
        }
    };
    private final JTable httpResponseJTable = new JTable(httpTableModel)
    {
        public boolean isCellEditable(int row, int column) {
            return false;
        }
        public Object getValueAt(int row, int column) {
            try {
                if(apiTableModel.getRowCount() > 0){ setSelectedData();}
            }
            catch(Exception e){
                return super.getValueAt(row, column);
            }
            return super.getValueAt(row, column);
        }
    };
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private JSplitPane splitPaneLeftAndRight;
    private JSplitPane splitPaneRight;
    private JSplitPane splitPaneLeft;
    private IMessageEditor requestViewer;
    private IMessageEditor responseViewer;

    private int apiTableSelectedRow = 0;
    private int httpTableSelectedRow = 0;
    private StringBuilder sb = new StringBuilder();

    private HashMap<String, String> apiMap = new HashMap<String, String>();
    private HashMap<String, List<apiListItem>> httpMap = new HashMap<String, List<apiListItem>>();;

    public void registerExtenderCallbacks(@NotNull IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        helpers = callbacks.getHelpers();
        callbacks.setExtensionName("sample extension");
        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {

                apiResponseJTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
//                apiModelJTable.setRowSelectionInterval(0,0);
                apiResponseJTable.getSelectionModel().addListSelectionListener(new ListSelectionListener(){
                    public void valueChanged(ListSelectionEvent event) {
                        setSelectedData();
                    }
                });
                httpResponseJTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
                //httpResponseJTable.setRowSelectionInterval(0,0);
                httpResponseJTable.getSelectionModel().addListSelectionListener(new ListSelectionListener(){
                    public void valueChanged(ListSelectionEvent event) {
                        setSelectedData();
                    }
                });
                //httpResponseJTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
                splitPaneLeft = new JSplitPane(JSplitPane.VERTICAL_SPLIT); //Left Component
                splitPaneRight = new JSplitPane(JSplitPane.VERTICAL_SPLIT); //Right component
                splitPaneLeft.setDividerLocation(300);

                // table of log entries on the left side of the split pane
                JScrollPane apiLogScrollPane = new JScrollPane(apiResponseJTable);
                JScrollPane httpResponseScrollPane = new JScrollPane(httpResponseJTable);
                splitPaneLeft.setTopComponent(apiLogScrollPane);
                splitPaneLeft.setBottomComponent(httpResponseScrollPane);

                // tabs with request/response viewers on the right side of the split pane
                JTabbedPane rightPaneTabs = new JTabbedPane();
                requestViewer = callbacks.createMessageEditor(BurpExtender.this, false);
                responseViewer = callbacks.createMessageEditor(BurpExtender.this, false);
                rightPaneTabs.addTab("Request", requestViewer.getComponent());
                rightPaneTabs.addTab("Response", responseViewer.getComponent());
                splitPaneRight.setRightComponent(rightPaneTabs);

                //Everything that's displayed in the tab.
                splitPaneLeftAndRight = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, splitPaneLeft, splitPaneRight);

                // customize our UI components
                callbacks.customizeUiComponent(splitPaneLeftAndRight);
                callbacks.customizeUiComponent(splitPaneRight);
                callbacks.customizeUiComponent(apiResponseJTable);
                callbacks.customizeUiComponent(httpResponseJTable);
                callbacks.customizeUiComponent(apiLogScrollPane);
                callbacks.customizeUiComponent(httpResponseScrollPane);
                callbacks.customizeUiComponent(rightPaneTabs);

                callbacks.addSuiteTab(BurpExtender.this);

                callbacks.registerHttpListener(BurpExtender.this);
            }
        });
    }

    @Override
    public String getTabCaption() {
        return "DTP Updated";
    } //Dipendra, Taylor & Paul. ;)

    @Override
    public Component getUiComponent() {
        return splitPaneLeftAndRight;
    }

    /*
        I think what we need to do here is just actually process the message. That is to say parse it out, and call the
        other method(s) to do their part.
    */
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        // only process responses

        if (!messageIsRequest) {
            String apiKey = processAPI_Key(messageInfo);
            String apiValue = processAPI_Value(apiKey, messageInfo);
            processAPIKeyValuePair(apiKey,apiValue);
            processHTTPKeyValuePair(apiValue, messageInfo);

            int row = apiTableModel.getRowCount();
            //Maybe don't do this next part. We need to evaluate when we're adding stuff, and if it should be unique.
            apiTableModel.addRow(new Object[]{apiKey});
            apiTableModel.fireTableRowsInserted(row, row+1);

        }
        setSelectedData();
    }

    // find out what to display. Called by the processHttpMessage and getValueAt.
    public void setSelectedData(){
        boolean hasChanged = false;
        if(apiTableSelectedRow != apiResponseJTable.getSelectedRow() && apiResponseJTable.getSelectedRow() > 0) {
            hasChanged = true;
            apiTableSelectedRow = apiResponseJTable.getSelectedRow();
            httpTableSelectedRow = 0;
        }
        if(!hasChanged && httpTableSelectedRow > 0 ){
            httpTableSelectedRow = httpResponseJTable.getSelectedRow();
        }
        else{
            httpTableSelectedRow = 0; // Default. When we don't know what else is going on.
        }
        String key = apiTableModel.getValueAt(apiTableSelectedRow,0).toString();
        List<apiListItem> Value = httpMap.get(apiMap.get(key));
        httpTableModel.setRowCount(0);
        for (apiListItem apli : Value) {
            httpTableModel.addRow(new Object[]{apli.key});
        }
        httpTableModel.fireTableRowsInserted(0, httpTableModel.getRowCount());
        setSelectedHTTP(httpTableSelectedRow);
    }

    public void setSelectedHTTP(int row){
        //httpResponseJTable.setRowSelectionInterval(row,row);
        setTabs(httpTableModel.getValueAt(row,0).toString());
    }
    public void setTabs(String key){
        requestViewer.setMessage(httpMap.get(key).get(httpTableSelectedRow).messageInfo.getRequest(), true);
        responseViewer.setMessage(httpMap.get(key).get(httpTableSelectedRow).messageInfo.getResponse(), false);
    }
    public String processAPI_Key(@NotNull IHttpRequestResponse messageInfo){
        sb.setLength(0);
        String request = new String(messageInfo.getRequest(), StandardCharsets.UTF_8);
        String[] requestTokens = request.split(" ");
        sb.append(requestTokens[0]);
        sb.append(" ");
        sb.append(requestTokens[1]);
        String apiKey = sb.toString();
        sb.setLength(0);
        return apiKey;
    }
    public String processAPI_Value(String key, @NotNull IHttpRequestResponse messageInfo){
        String response = new String(messageInfo.getResponse(), StandardCharsets.UTF_8);
        String[] responseTokens = response.split(" ");
        sb.append(key);
        sb.append(" ");
        sb.append(responseTokens[1]);
        String apiValue = sb.toString();
        sb.setLength(0);
        return apiValue;
    }
    public void processAPIKeyValuePair(String key, String value){
        if(!apiMap.containsKey(key)){
            apiMap.put(key,value);
        }
    }
    public void processHTTPKeyValuePair(String key, IHttpRequestResponse messageInfo){
    apiListItem temp = new apiListItem(key, messageInfo);
        if(!httpMap.containsKey(key)){
            List<apiListItem> ali = new ArrayList<>();
            ali.add(temp);
            httpMap.put(key, ali);
        }
        else{
            httpMap.get(key).add(temp);
        }
    }

    @Override
    public byte[] getRequest() {
        return currentlyDisplayedItem.getRequest();
    }

    @Override
    public byte[] getResponse() {
        return currentlyDisplayedItem.getResponse();
    }

    @Override
    public IHttpService getHttpService() {
        return currentlyDisplayedItem.getHttpService();
    }
    private record LogEntry(int tool, IHttpRequestResponse requestResponse, URL url) {
    }

    private record apiListItem(String key, IHttpRequestResponse messageInfo){
    }
}
