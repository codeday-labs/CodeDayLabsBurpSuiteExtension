// Debug using java -agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=*:5005 -jar burpsuite_community.jar
package burp;
import org.jetbrains.annotations.NotNull;
import java.awt.Component;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.ListSelectionModel;
import javax.swing.SwingUtilities;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import javax.swing.table.DefaultTableModel;

public class BurpExtender implements IBurpExtender, IHttpListener, ITab, IMessageEditorController {
// Start Variables
    private IHttpRequestResponse currentlyDisplayedItem;
    private String[] apiName = {"API Path"};
    private String[] httpName = {"HTTP Response"};
    private DefaultTableModel apiTableModel = new DefaultTableModel(apiName, 0);
    private DefaultTableModel httpTableModel = new DefaultTableModel(httpName, 0);
    private final JTable apiResponseJTable = new JTable(apiTableModel) {
        public boolean isCellEditable(int row, int column) {
            return false;
        }
        @Override
        public Object getValueAt(int row, int column) {
            return super.getValueAt(row, column);
        }
    };
    private final JTable httpResponseJTable = new JTable(httpTableModel) {
        public boolean isCellEditable(int row, int column) {
            return false;
        }
        public Object getValueAt(int row, int column) {
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
    private HashMap<String, List<apiListItem>> dictionaryMapThing = new HashMap<String, List<apiListItem>>();
// End Variables

// Start Record
    /*
     Used as members of a list, where key is the line displayed on the HTTP response table, and messageInfo
     Is the stuff that's in the tabs when that is selected.
     */
    private record apiListItem(String key, IHttpRequestResponse messageInfo) {
    }
// End Records

//Start No Touchy
    public void registerExtenderCallbacks(@NotNull IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        helpers = callbacks.getHelpers();
        callbacks.setExtensionName("sample extension");
        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                apiResponseJTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
                apiResponseJTable.getSelectionModel().addListSelectionListener(new ListSelectionListener() {
                    public void valueChanged(ListSelectionEvent event) {
                        setSelectedData();
                    }
                });
                apiResponseJTable.setRowSelectionAllowed(true);
                apiResponseJTable.setColumnSelectionAllowed(false);
                httpResponseJTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
                httpResponseJTable.getSelectionModel().addListSelectionListener(new ListSelectionListener() {
                    public void valueChanged(ListSelectionEvent event) {
                        setSelectedData();
                    }
                });
                httpResponseJTable.setRowSelectionAllowed(true);
                httpResponseJTable.setColumnSelectionAllowed(false);
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
//End No Touchy


// Process everything.
    /*
        I think what we need to do here is just actually process the message. That is to say parse it out, and call the
        other method(s) to do their part.
    */
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        if (!messageIsRequest) {
            // get the key and value
            String apiKey = processAPI_Key(messageInfo);
            String apiValue = processAPI_Value(apiKey, messageInfo);
            processDataSources(apiKey, apiValue, messageInfo);
            if(dictionaryMapThing.keySet().size() > 0){
                setSelectedData();
            }
        }
    }

    public void processDataSources(String key, String value, IHttpRequestResponse messageInfo) {
        apiListItem temp = new apiListItem(value, messageInfo);
        // If it's not in the dictionary, add it to the dictionary and the API list.
        if (!dictionaryMapThing.containsKey(key)) {
            int size = apiTableModel.getRowCount();
            List<apiListItem> ali = new ArrayList<>();
            ali.add(temp);
            dictionaryMapThing.put(key, ali);
            apiTableModel.addRow(new Object[]{key});
            apiTableModel.fireTableRowsInserted(size, apiTableModel.getRowCount());
        }
        else { //Already in the dictionary.
        // If the current message key is the same as the selected key, we need to also add the value to the http list...
            dictionaryMapThing.get(key).add(temp);//
        }
        apiResponseJTable.setRowSelectionInterval(apiTableSelectedRow,apiTableSelectedRow);
        setHTTPTable();
        setSelectedData();
    }


// End process everything.

// Process API (Top left table) stuff.

    public String processAPI_Key(@NotNull IHttpRequestResponse messageInfo) {
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

    public String processAPI_Value(String key, @NotNull IHttpRequestResponse messageInfo) {
        String response = new String(messageInfo.getResponse(), StandardCharsets.UTF_8);
        String[] responseTokens = response.split(" ");
        sb.append(key);
        sb.append(" ");
        sb.append(responseTokens[1]);
        String apiValue = sb.toString();
        sb.setLength(0);
        return apiValue;
    }
// End Process API Stuff.

// Process HTTP (Bottom Left Table) Stuff.

    private  void setHTTPTable(){
        int index = 0;
        //API Selection Hasn't Changed.
        if(httpTableModel.getRowCount() > 0){
            index = httpTableModel.getRowCount();
        }
        //only add in new elements.
        for (int i = index; i < dictionaryMapThing.get(apiResponseJTable.getValueAt(apiTableSelectedRow,0).toString()).size() ; i++) {
            String value = dictionaryMapThing.get(apiResponseJTable.getValueAt(apiTableSelectedRow,0).toString()).get(i).key;
            httpTableModel.addRow(new Object[]{value});
            httpTableModel.fireTableRowsInserted(index, httpTableModel.getRowCount());
        }
    }
// End Process HTTP Stuff.

// Process Tabs (The component on the right, with the full message info)

    public void setTabs() {
        requestViewer.setMessage(dictionaryMapThing.get(apiTableModel.getValueAt(apiTableSelectedRow,0)).get(httpTableSelectedRow).messageInfo.getRequest(), true);
        responseViewer.setMessage(dictionaryMapThing.get(apiTableModel.getValueAt(apiTableSelectedRow,0)).get(httpTableSelectedRow).messageInfo.getResponse(), false);
    }

// End Process Tabs
    //Do GUI Update Stuff.
    // find out what to display. Called by the processHttpMessage and getValueAt.
public void setSelectedData() {
// If we don't have data, we can't do anything.
    if(dictionaryMapThing.keySet().size() > 0){
        boolean hasChanged = false;
        //API section
        //Selected and "last selected" not the same.
        if(apiTableSelectedRow != apiResponseJTable.getSelectedRow()){
            hasChanged = true;
            //First entry will be -1
            if(apiResponseJTable.getSelectedRow() >= 0){
                apiTableSelectedRow = apiResponseJTable.getSelectedRow();
            }
            apiResponseJTable.setRowSelectionInterval(apiTableSelectedRow,apiTableSelectedRow);
        }
        //HTTP Section
        //API Table changed
        if(hasChanged){ // Always set the HTTP table to zero, because it's a new table...
            httpTableSelectedRow = 0;
            httpTableModel.setRowCount(0);
            setHTTPTable();
            httpResponseJTable.setRowSelectionInterval(httpTableSelectedRow,httpTableSelectedRow);
        }
        // API Table didn't change.
        else{
            //Change in the HTTP table index
            //First entry will be -1
            if(httpResponseJTable.getSelectedRow() >= 0){
                httpTableSelectedRow = httpResponseJTable.getSelectedRow();
            }
        }
        setHTTPTable();
        setTabs();
    }
}
// End GUI Stuff.

    // Functions for interpreting data that's sent from the Burp software.
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
// End Functions for interpreting data that's sent from the Burp software.

    // Functions for displaying the tab on Burp.
    // The tab's name.
    @Override
    public String getTabCaption() {
        return "DTP Updated";
    } //Dipendra, Taylor & Paul. ;)

    // The GUI component (everything that's displayed)
    @Override
    public Component getUiComponent() {
        return splitPaneLeftAndRight;
    }
}
