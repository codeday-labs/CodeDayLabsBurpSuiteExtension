package burp;
import java.awt.*;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableModel;

public class BurpExtender extends AbstractTableModel implements IBurpExtender, IHttpListener, ITab, IMessageEditorController {
    private final List<LogEntry> log1 = new ArrayList<LogEntry>();
    private final List<LogEntry> log2 = new ArrayList<LogEntry>();

    private final Table apiLogTable = new Table(BurpExtender.this, "log table 1", log1);
    private final Table2 httpsResponseLogTable = new Table2(new MyTableModel(), "log table 2", log2);
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private JSplitPane leftSplitPane;
    private JSplitPane rightSplitPane;
    private IMessageEditor requestViewer;
    private IMessageEditor responseViewer;
    private IHttpRequestResponse currentlyDisplayedItem;

    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        helpers = callbacks.getHelpers();
        callbacks.setExtensionName("sample extension");

        SwingUtilities.invokeLater(new Runnable() {

            @Override
            public void run() {
                leftSplitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
                rightSplitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
                leftSplitPane.setDividerLocation(300);

                // table of log entries
                JScrollPane scrollPane = new JScrollPane(apiLogTable);
                JScrollPane scrollPane2 = new JScrollPane(httpsResponseLogTable);
                leftSplitPane.setTopComponent(scrollPane);
                leftSplitPane.setBottomComponent(scrollPane2);

                // tabs with request/response viewers
                JTabbedPane tabs = new JTabbedPane();
                requestViewer = callbacks.createMessageEditor(BurpExtender.this, false);
                responseViewer = callbacks.createMessageEditor(BurpExtender.this, false);
                tabs.addTab("Request", requestViewer.getComponent());
                tabs.addTab("Response", responseViewer.getComponent());
                rightSplitPane.setRightComponent(tabs);

                leftSplitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, leftSplitPane, rightSplitPane);

                // customize our UI components
                callbacks.customizeUiComponent(leftSplitPane);
                callbacks.customizeUiComponent(rightSplitPane);
                callbacks.customizeUiComponent(apiLogTable);
                callbacks.customizeUiComponent(httpsResponseLogTable);
                callbacks.customizeUiComponent(scrollPane);
                callbacks.customizeUiComponent(scrollPane2);
                callbacks.customizeUiComponent(tabs);

                callbacks.addSuiteTab(BurpExtender.this);

                callbacks.registerHttpListener(BurpExtender.this);
            }
        });
    }

    @Override
    public String getTabCaption() {
        return "Test";
    }

    @Override
    public Component getUiComponent() {
        return leftSplitPane;
    }

    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        // only process responses
        if (!messageIsRequest) {
            // create a new log entry with the message details
            synchronized (apiLogTable.table_log) {
                int row = apiLogTable.table_log.size();
                apiLogTable.table_log.add(new LogEntry(toolFlag, callbacks.saveBuffersToTempFiles(messageInfo),
                        helpers.analyzeRequest(messageInfo).getUrl()));
                fireTableRowsInserted(row, row);
            }
            synchronized (httpsResponseLogTable.table_log) {
                int row = httpsResponseLogTable.table_log.size();
                httpsResponseLogTable.table_log.add(new LogEntry(toolFlag, callbacks.saveBuffersToTempFiles(messageInfo),
                        helpers.analyzeRequest(messageInfo).getUrl()));
                fireTableRowsInserted(row, row);

            }
        }
    }


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
        switch (columnIndex) {
            case 0:
                return "API Routes";
//            case 1:
//                return "URL";
            default:
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

        switch (columnIndex) {
            case 0:
                String s = new String(logEntry.requestResponse.getRequest(), StandardCharsets.UTF_8);
               // return s; //callbacks.getToolName(logEntry.tool);
            case 1:
                return logEntry.url.toString();
            default:
                return "";
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

    private static class LogEntry {
        final int tool;
        final IHttpRequestResponsePersisted requestResponse;
        final URL url;



        LogEntry(int tool, IHttpRequestResponsePersisted requestResponse, URL url) {
            this.tool = tool;
            this.requestResponse = requestResponse;
            this.url = url;

        }
    }

        //
// extend JTable to handle cell selection
//

    // Table for 2nd log set to use
    public class MyTableModel extends AbstractTableModel {

        //
        // extend AbstractTableModel
        //


        @Override
        public int getRowCount() { return log2.size(); }

        @Override
        public int getColumnCount() {
            return 1;
        }

        @Override
        public String getColumnName(int columnIndex) {
            switch (columnIndex) {
                case 0:
                    return "HTTP Response";
//            case 1:
//                return "URL";
                default:
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
            LogEntry logEntry = log2.get(rowIndex);

            switch (columnIndex) {
                case 0:
                    String s = new String(logEntry.requestResponse.getResponse(), StandardCharsets.UTF_8);
                    return s; //callbacks.getToolName(logEntry.tool);
                case 1:
                    return logEntry.url.toString();
                default:
                    return "";

                // return log2.get(rowIndex);

            }
        }
    }

    private class Table extends JTable {
        public String tableName;
        public List<LogEntry> table_log;

        public Table(TableModel tableModel, String tableName, List<LogEntry> log) {
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
    }

    //class LogEntry:
//
//    def init (self, tool, requestResponse, url):
//        self._tool = tool
//        self._requestResponse = requestResponse
//        self._url = url
//        return

        //
// class to hold details of each log entry
//

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
            //String row_data = this.table_log.get(row);
            requestViewer.setMessage(logEntry.requestResponse.getRequest(), true);
            responseViewer.setMessage(logEntry.requestResponse.getResponse(), false);
            currentlyDisplayedItem = logEntry.requestResponse;

            super.changeSelection(row, col, toggle, extend);
        }
    }
}

