package burp;

import java.awt.*;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Dictionary;
import java.util.Hashtable;
import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableModel;

public class BurpExtender extends AbstractTableModel implements IBurpExtender, IHttpListener, ITab, IMessageEditorController {
    private final String[] apiName = {"API Path"};
    private final String[] httpName = {"HTTP Response"};
    private final DefaultTableModel apiTableModel = new DefaultTableModel(apiName, 0);
    private final DefaultTableModel httpTableModel = new DefaultTableModel(httpName, 0);
    private final JTable apiModelJTable = new JTable(apiTableModel)
    {
        public boolean isCellEditable(int row, int column) {
            return false;
        }
    };
    private final JTable httpResponseJTable = new JTable(httpTableModel)
    {
        public boolean isCellEditable(int row, int column) {
            return false;
        }
    };
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private JSplitPane splitPaneLeftAndRight;
    private JSplitPane splitPaneLeft;
    private JSplitPane splitPaneRight;
    private IMessageEditor requestViewer;
    private IMessageEditor responseViewer;
    private IHttpRequestResponse currentlyDisplayedItem;
    private Integer apiTableSelectedRow = 0;
    private Integer httpTableSelectedRow = 0;

    private final Dictionary<String, String> dictApi = new Hashtable<>();
    private final Dictionary<String, LogEntryDict> dictHttp = new Hashtable<>();

    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        helpers = callbacks.getHelpers();
        callbacks.setExtensionName("sample extension");
        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                apiModelJTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
                httpResponseJTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);

                splitPaneLeft = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
                splitPaneRight = new JSplitPane(JSplitPane.VERTICAL_SPLIT); //right component
                splitPaneLeft.setDividerLocation(300);

                // table of log entries on the left side of the split pane
                JScrollPane apiLogScrollPane = new JScrollPane(apiModelJTable);
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
                callbacks.customizeUiComponent(apiModelJTable);
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
            int row = apiModelJTable.getRowCount();
            LogEntry le = new LogEntry(toolFlag, callbacks.saveBuffersToTempFiles(messageInfo),
                    helpers.analyzeRequest(messageInfo).getUrl());
            String request = new String(le.requestResponse.getRequest(), StandardCharsets.UTF_8);
            String[] requestTokens = request.split(" ");
            String parsedRequest = requestTokens[0] + " " + requestTokens[1];
            StringBuilder sbApi = new StringBuilder();

            sbApi.append(parsedRequest);
            sbApi.append(" ");
            String strEntryApi = sbApi.toString();
            apiTableModel.addRow(new Object[]{strEntryApi});
            apiTableModel.fireTableRowsInserted(row, row);

            /*We need to modify the section below here to have logic on selection of the item to display on right
                    * pane so we can pass the call to it from the first log. There's a few ways to go about this.
                    *
                    * Right now this is just placeholder info (It's the same data). */
            int row1 = httpResponseJTable.getRowCount();
            String response = new String(le.requestResponse.getResponse(), StandardCharsets.UTF_8);
            String[] responseTokens = response.split(" ");
            String parsedResponse = responseTokens[0] + " " + responseTokens[1];
            StringBuilder sbHttp = new StringBuilder();

            LogEntryDict logDict = new LogEntryDict(parsedResponse, messageInfo);
            dictApi.put(request, parsedRequest);
            dictHttp.put(parsedRequest, logDict);

            sbHttp.append(parsedResponse);
            sbHttp.append(" ");

            /*
               Careful. I've got this next line set up to be the same string as above. Once we go to
               start making this useful we'll need to update that. This whole section should be changed.
               * */
            String strEntryHttp = sbHttp.toString();
            httpTableModel.addRow(new Object[]{strEntryHttp});
            httpTableModel.fireTableRowsInserted(row1, row1);

            // Update the tabs. Need to get the logic for this right. Not currently updating correctly.
            requestViewer.setMessage(dictHttp.get(parsedRequest).requestResponse.getRequest(), true);
            responseViewer.setMessage(dictHttp.get(parsedRequest).requestResponse.getResponse(), false);
            currentlyDisplayedItem = dictHttp.get(parsedRequest).requestResponse;
        }
        setSelectedData(messageInfo);
    }

    // find out what to display. Called by the processHttpMessage and getValueAt.
    public void setSelectedData(IHttpRequestResponse messageInfo){

        // Change happened in the top left pane.
        //Need to figure out the logic on updating tables here based on the dictionaries.
        if(apiTableSelectedRow != apiModelJTable.getSelectedRow()){
            apiTableSelectedRow = apiModelJTable.getSelectedRow();
            httpTableSelectedRow = 0;
        }
        // See if anything has changed in bottom left pane.
        else{
            /*/Select the data from the top left pane as key, and with the list of values in the bottom
               select the one that corresponds to the currently selected value (httpTableSelectedRow), and display
               the information relevant to it.
            * */

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

            @Override
            public Object getValueAt(int rowIndex, int columnIndex){
                Object logEntry = apiModelJTable.getValueAt(rowIndex, columnIndex);
                if (columnIndex == 0) {
                    return logEntry;
                } else {
                    return "";
                }
            }

                private record LogEntryDict(String httpResponse, IHttpRequestResponse requestResponse) {
                }

                private record LogEntry(int tool, IHttpRequestResponsePersisted requestResponse, URL url) {
                }

                // Don't do anything with these. They're artifacts from a necessary (currently) thing we can't get rid of.
                @Override
                public int getRowCount() {
                    return 0;
                }

                @Override
                public int getColumnCount() {
                    return 0;
                }
                // End artifacts. We may end up using those, but I have no purpose for them at the moment.
            }