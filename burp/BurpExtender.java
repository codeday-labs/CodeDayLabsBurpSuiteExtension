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
import javax.swing.table.TableModel;

public class BurpExtender extends AbstractTableModel implements IBurpExtender, IHttpListener, ITab, IMessageEditorController {
    private final List<LogEntry> log1 = new ArrayList<>();
    private final List<LogEntry> log2 = new ArrayList<>();

    private final Table logTable1 = new Table(BurpExtender.this, "log table 1", log1);
    private final Table2 logTable2 = new Table2(new MyTableModel(), "log table 2", log2);
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private JSplitPane splitPane;
    private JSplitPane splitPane2;
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
                splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
                splitPane2 = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
                splitPane.setDividerLocation(300);

                // table of log entries
                JScrollPane scrollPane = new JScrollPane(logTable1);
                JScrollPane scrollPane2 = new JScrollPane(logTable2);
                splitPane.setTopComponent(scrollPane);
                splitPane.setBottomComponent(scrollPane2);
                // tabs with request/response viewers
                JTabbedPane tabs = new JTabbedPane();
                requestViewer = callbacks.createMessageEditor(BurpExtender.this, false);
                responseViewer = callbacks.createMessageEditor(BurpExtender.this, false);
                tabs.addTab("Request", requestViewer.getComponent());
                tabs.addTab("Response", responseViewer.getComponent());
                splitPane2.setRightComponent(tabs);

                splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, splitPane, splitPane2);

                // customize our UI components
                callbacks.customizeUiComponent(splitPane);
                callbacks.customizeUiComponent(splitPane2);
                callbacks.customizeUiComponent(logTable1);
                callbacks.customizeUiComponent(logTable2);
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
        return splitPane;
    }

    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        // only process responses
        if (!messageIsRequest) {
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
    }
}