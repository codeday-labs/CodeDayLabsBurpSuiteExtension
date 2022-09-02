package burp;

import java.awt.*;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Dictionary;
import java.util.Hashtable;
import java.util.List;
import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableModel;

public class BurpExtender extends AbstractTableModel implements IBurpExtender, IHttpListener, ITab, IMessageEditorController {
    private final List<LogEntry> log1 = new ArrayList<>();
    private final List<LogEntry> log2 = new ArrayList<>();

    private final Table logTable1 = new Table(BurpExtender.this, "log table 1", log1);
    private final Table2 logTable2 = new Table2(new MyTableModel(), "log table 2", log2);
    private String[] apiName = {"API Path"};
    private String[] httpName = {"HTTP Response"};
    private DefaultTableModel apiTableModel = new DefaultTableModel(apiName, 0);
    private DefaultTableModel httpTableModel = new DefaultTableModel(httpName, 0);
    private final JTable apiModelJTable = new JTable(apiTableModel);
    private final JTable httpResponseJTable = new JTable(httpTableModel);
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private JSplitPane splitPaneLeft;
    private JSplitPane splitPaneRight;
    private JSplitPane splitPaneLeftContainer;
    private IMessageEditor requestViewer;
    private IMessageEditor responseViewer;
    private IHttpRequestResponse currentlyDisplayedItem;

    private Dictionary<Integer, String> dict = new Hashtable<Integer, String>();
    private Dictionary<Integer, String> dict2 = new Hashtable<Integer, String>();

    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {

        this.callbacks = callbacks;
        helpers = callbacks.getHelpers();
        callbacks.setExtensionName("sample extension");
        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                splitPaneLeftContainer = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
                splitPaneRight = new JSplitPane(JSplitPane.VERTICAL_SPLIT); //right component
                splitPaneLeftContainer.setDividerLocation(300);

                // table of log entries on the left side of the split pane
                JScrollPane apiLogScrollPane = new JScrollPane(apiModelJTable);
                JScrollPane httpResponseScrollPane = new JScrollPane(httpResponseJTable);
                splitPaneLeftContainer.setTopComponent(apiLogScrollPane);
                splitPaneLeftContainer.setBottomComponent(httpResponseScrollPane);

                // tabs with request/response viewers on the right side of the split pane
                JTabbedPane rightPaneTabs = new JTabbedPane();
                requestViewer = callbacks.createMessageEditor(BurpExtender.this, false);
                responseViewer = callbacks.createMessageEditor(BurpExtender.this, false);
                rightPaneTabs.addTab("Request", requestViewer.getComponent());
                rightPaneTabs.addTab("Response", responseViewer.getComponent());
                splitPaneRight.setRightComponent(rightPaneTabs);
                splitPaneLeft = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, splitPaneLeftContainer, splitPaneRight);

                // customize our UI components
                callbacks.customizeUiComponent(splitPaneLeft);
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
        return splitPaneLeft;
    }

    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        // only process responses
        if (!messageIsRequest) {
<<<<<<< HEAD
            // create a new log entry with the message details
            synchronized (logTable1.table_log) {
                int row = logTable1.table_log.size();
                logTable1.table_log.add(new LogEntry(toolFlag, callbacks.saveBuffersToTempFiles(messageInfo),
                        helpers.analyzeRequest(messageInfo).getUrl()));
                fireTableRowsInserted(row, row);
            }
            synchronized (logTable2.table_log) {
                int row = logTable2.table_log.size();
                logTable2.table_log.add(new LogEntry(toolFlag, callbacks.saveBuffersToTempFiles(messageInfo),
                        helpers.analyzeRequest(messageInfo).getUrl()));
                fireTableRowsInserted(row, row);
            }
        }
    }

        //
        // extend AbstractTableModel
        //

    @Override
    public int getRowCount() {
        return log1.size();
    }

    @Override
    public int getColumnCount() {
        return 1;
    }

    @Override
    public String getColumnName(int columnIndex) {
        if (columnIndex == 0) {
            return "API Routes";
        }
        else {
            return "";
        }
    }

    @Override
    public Class<?> getColumnClass(int columnIndex) {
        return String.class;
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        LogEntry logEntry = log1.get(rowIndex);

        if (columnIndex == 0) {
            String s = new String(logEntry.requestResponse.getRequest(), StandardCharsets.UTF_8);
            String[] tokens = s.split(" ");
            dict.put(0, tokens[0]);
            dict.put(1, tokens[1]);
            dict.put(2, tokens[2]);
            //String t = dict.toString();                                                                                                                                                                                                             ;
            //String s = new String(logEntry.requestResponse.getRequest(), StandardCharsets.UTF_8);
            return dict.get(0) + " " + dict.get(1); //callbacks.getToolName(logEntry.tool);
        }
        else {
            return "";
            int row = apiModelJTable.getRowCount();
            LogEntry le = new LogEntry(toolFlag, callbacks.saveBuffersToTempFiles(messageInfo),
                    helpers.analyzeRequest(messageInfo).getUrl());
            StringBuilder sb = new StringBuilder();

            sb.append(callbacks.getToolName(le.tool));
            sb.append(" ");
            sb.append(le.url);
            sb.append(" ");
            String strEntry = sb.toString();
            apiTableModel.addRow(new Object[]{strEntry});
            apiTableModel.fireTableRowsInserted(row, row);

            /*We need to modify the section below here to have logic on selection of the item to display on right
             * pane so we can pass the call to it from the first log. There's a few ways to go about this.
             *
             * Right now this is just placeholder info (It's the same data). */
            //int row1 = httpResponseJTable.getRowCount();
            LogEntry le1 = new LogEntry(toolFlag, callbacks.saveBuffersToTempFiles(messageInfo),
                    helpers.analyzeRequest(messageInfo).getUrl());
            sb.append(callbacks.getToolName(le1.tool));

                /*
                Careful. I've got this next line set up to be the same string as above. Once we go to
                start making this useful we'll need to update that. This whole section should be changed.
                * */
            httpTableModel.addRow(new Object[]{strEntry});
            fireTableRowsInserted(row, row);

            // Update the tabs. Need to get the logic for this right. Not currently updating correctly.
            requestViewer.setMessage(le1.requestResponse.getRequest(), true);
            responseViewer.setMessage(le1.requestResponse.getResponse(), false);
            currentlyDisplayedItem = le1.requestResponse;
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
    public Object getValueAt(int rowIndex, int columnIndex) {
        Object logEntry = apiModelJTable.getValueAt(rowIndex, columnIndex);
        if (columnIndex == 0) {
//        String s = new String(logEntry.requestResponse.getRequest(), StandardCharsets.UTF_8);
//        return s; //callbacks.getToolName(logEntry.tool);
            return logEntry;
        } else {
            return "";
        }
    }

<<<<<<< HEAD
// extend JTable to handle cell selection

    // Table for 2nd log set to use
    public class MyTableModel extends AbstractTableModel {

        // extend AbstractTableModel

        @Override
        public int getRowCount() {
            return log2.size();
        }

        @Override
        public int getColumnCount() {
            return 1;
        }

        @Override
        public String getColumnName(int columnIndex) {
            if (columnIndex == 0) {
                return "HTTP Response";
            } else {
                return "";
            }
        }

        @Override
        public Class<?> getColumnClass(int columnIndex) {
            return String.class;
        }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            // Adele note: ignoring rowIndex for now
            LogEntry logEntry = log1.get(rowIndex);

            if (logTable1.isRowSelected(rowIndex)) {
                String t = new String(logEntry.requestResponse.getResponse(), StandardCharsets.UTF_8);
                String[] tokens = t.split(" ");
                dict2.put(0, tokens[0]);
                dict2.put(1, tokens[1]);
                //String t = dict2.toString();
                //String t = new String(logEntry.requestResponse.getResponse(), StandardCharsets.UTF_8);
                return dict2.get(0) + " " + dict2.get(1); //callbacks.getToolName(logEntry.tool);
            }
            return "";
        }

        private record LogEntry(int tool, IHttpRequestResponsePersisted requestResponse, URL url) {
    }

    // Don't do anything with these. They're artifacts from a necessary (currently) thing we can't get rid of.
    @Override
    public int getRowCount() {
        return 0;
    }

// class to hold details of each log entry

    private class Table2 extends JTable {
        public String tableName;
        public List<LogEntry> table_log;

        public Table2(TableModel tableModel, String tableName, List<LogEntry> log) {
            super(tableModel);
            this.tableName = tableName;
            this.table_log = log;

        }

        @Override
        public void changeSelection(int row, int col, boolean toggle, boolean extend) {
            // show the log entry for the selected row
            LogEntry logEntry = this.table_log.get(row);
            requestViewer.setMessage(logEntry.requestResponse.getRequest(), true);
            responseViewer.setMessage(logEntry.requestResponse.getResponse(), false);
            currentlyDisplayedItem = logEntry.requestResponse;

            super.changeSelection(row, col, toggle, extend);
        }

    @Override
    public int getColumnCount() {
        return 0;

    }
    // End artifacts. We may end up using those, but I have no purpose for them at the moment.
}