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
    private final List<LogEntry> apiLog = new ArrayList<LogEntry>();
    private final List<LogEntry> httpResponseLog = new ArrayList<LogEntry>();
    private final Table apiLogTable = new Table(new MyTableModel("API Routes"), apiLog);
    private final Table httpResponseTable = new Table(new MyTableModel2("HTTP Response"), httpResponseLog);
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private JSplitPane splitPaneLeft;
    private JSplitPane splitPaneRight;
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
                splitPaneLeft = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
                splitPaneRight = new JSplitPane(JSplitPane.VERTICAL_SPLIT); //right component
                splitPaneLeft.setDividerLocation(300);

                // table of log entries on the left side of the split pane
                JScrollPane apiLogScrollPane = new JScrollPane(apiLogTable);
                JScrollPane httpResponseScrollPane = new JScrollPane(httpResponseTable);
                splitPaneLeft.setTopComponent(apiLogScrollPane);
                splitPaneLeft.setBottomComponent(httpResponseScrollPane);

                // tabs with request/response viewers on the right side of the split pane
                JTabbedPane rightPaneTabs = new JTabbedPane();
                requestViewer = callbacks.createMessageEditor(BurpExtender.this, false);
                responseViewer = callbacks.createMessageEditor(BurpExtender.this, false);
                rightPaneTabs.addTab("Request", requestViewer.getComponent());
                rightPaneTabs.addTab("Response", responseViewer.getComponent());
                splitPaneRight.setRightComponent(rightPaneTabs);
                splitPaneLeft = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, splitPaneLeft, splitPaneRight);

                // customize our UI components
                callbacks.customizeUiComponent(splitPaneLeft);
                callbacks.customizeUiComponent(splitPaneRight);
                callbacks.customizeUiComponent(apiLogTable);
                callbacks.customizeUiComponent(httpResponseTable);
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
            // create a new log entry with the message details
            //try {Thread.sleep(200);} catch (InterruptedException e) {/*Do Nothing.*/}
            synchronized (apiLogTable.table_log) {
                int row = apiLogTable.table_log.size();
                apiLogTable.table_log.add(new LogEntry(toolFlag, callbacks.saveBuffersToTempFiles(messageInfo),
                        helpers.analyzeRequest(messageInfo).getUrl()));
                fireTableRowsInserted(row, row);
            }
            synchronized (httpResponseTable.table_log) {
                int row = httpResponseTable.table_log.size();
                httpResponseTable.table_log.add(new LogEntry(toolFlag, callbacks.saveBuffersToTempFiles(messageInfo),
                        helpers.analyzeRequest(messageInfo).getUrl()));
                fireTableRowsInserted(row, row);
            }
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

    // Don't do anything with these. They're artifacts from a necessary (currently) thing we can't get rid of.
    @Override
    public int getRowCount() {
        return 0;
    }

    @Override
    public int getColumnCount() {
        return 0;
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        return null;
    }

    // Table for 1st log set to use
    public class MyTableModel extends AbstractTableModel {
        String tableName;

        // extend AbstractTableModel
        MyTableModel(String name) {
            tableName = name;
        }

        @Override
        public int getRowCount() {
            return apiLog.size();
        }

        @Override
        public int getColumnCount() {
            return 1;
        }

        @Override
        public String getColumnName(int columnIndex) {
            return tableName;
        }

        @Override
        public Class<?> getColumnClass(int columnIndex) {
            return String.class;
        }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {

            LogEntry logEntry = apiLog.get(rowIndex);

            switch (columnIndex) {
                case 0:
                    String s = new String(logEntry.requestResponse.getRequest(), StandardCharsets.UTF_8);
                    String[] tokens = s.split(" ");
                    dict.put(0, tokens[0]);
                    dict.put(1, tokens[1]);
                    dict.put(2, tokens[2]);
                    //String t = dict.toString();                                                                                                                                                                                                             ;
                    //String s = new String(logEntry.requestResponse.getRequest(), StandardCharsets.UTF_8);
                    return dict.get(0) + " " + dict.get(1); //callbacks.getToolName(logEntry.tool);
                //case 1:
                //return logEntry.url.toString();
                default:
                    return "";
            }
        }
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

    // Table for 2nd log set to use
    public class MyTableModel2 extends AbstractTableModel {
        String tableName;

        // extend AbstractTableModel
        MyTableModel2(String name) {
            tableName = name;
        }

        @Override
        public int getRowCount() {
            return httpResponseLog.size();
        }

        @Override
        public int getColumnCount() {
            return 1;
        }

        @Override
        public String getColumnName(int columnIndex) {
            return tableName;
        }

        @Override
        public Class<?> getColumnClass(int columnIndex) {
            return String.class;
        }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            // Adele note: ignoring rowIndex for now
            LogEntry logEntry = apiLog.get(rowIndex);

            switch (columnIndex) {
                case 0:
                    String t = new String(logEntry.requestResponse.getResponse(), StandardCharsets.UTF_8);
                    String[] tokens = t.split(" ");
                    dict2.put(0, tokens[0]);
                    dict2.put(1, tokens[1]);
                    //String t = dict2.toString();
                    //String t = new String(logEntry.requestResponse.getResponse(), StandardCharsets.UTF_8);
                    return dict2.get(0) + " " + dict2.get(1); //callbacks.getToolName(logEntry.tool);
                    //case 1:
                    //return logEntry.url.toString();
                default:
                    return "";
            }
        }
    }

    private class Table extends JTable {
        public String tableName;
        public List<LogEntry> table_log;
        TableModel TM;

        public Table(TableModel tableModel, List<LogEntry> log) {
            super(tableModel);
            TM = tableModel;
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