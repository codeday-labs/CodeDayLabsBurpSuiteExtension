package burp;

import java.awt.*;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableModel;

public class BurpExtender extends AbstractTableModel implements IBurpExtender, IHttpListener, ITab, IMessageEditorController {
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private JSplitPane splitPane;
    private JSplitPane splitPane2;
    private IMessageEditor requestViewer;
    private IMessageEditor responseViewer;
    private final List<LogEntry> log = new ArrayList<LogEntry>();
    private IHttpRequestResponse currentlyDisplayedItem;

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
                Table logTable = new Table(BurpExtender.this);
                Table logTable2 = new Table(BurpExtender.this);
                JScrollPane scrollPane = new JScrollPane(logTable);
                JScrollPane scrollPane2 = new JScrollPane(logTable2);
                splitPane.setLeftComponent(scrollPane);
                splitPane.setRightComponent(scrollPane2);

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
                callbacks.customizeUiComponent(logTable);
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

    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo){
        // only process responses
        if (!messageIsRequest)
        {
            // create a new log entry with the message details
            synchronized(log)
            {
                int row = log.size();
                log.add(new LogEntry(toolFlag, callbacks.saveBuffersToTempFiles(messageInfo),
                        helpers.analyzeRequest(messageInfo).getUrl()));
                fireTableRowsInserted(row, row);
            }
        }
    }

    //
    // extend AbstractTableModel
    //

    @Override
    public int getRowCount()
    {
        return log.size();
    }

    @Override
    public int getColumnCount()
    {
        return 1;
    }

    @Override
    public String getColumnName(int columnIndex)
    {
        switch (columnIndex)
        {
            case 0:
                return "API Routes";
//            case 1:
//                return "URL";
            default:
                return "";
        }
    }

    @Override
    public Class<?> getColumnClass(int columnIndex)
    {
        return String.class;
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex)
    {
        LogEntry logEntry = log.get(rowIndex);

        switch (columnIndex)
        {
            case 0:
                return logEntry.url.getPath(); //callbacks.getToolName(logEntry.tool);
            case 1:
                return logEntry.url.toString();
            default:
                return "";
        }
    }

    @Override
    public byte[] getRequest()
    {
        return currentlyDisplayedItem.getRequest();
    }

    @Override
    public byte[] getResponse()
    {
        return currentlyDisplayedItem.getResponse();
    }

    @Override
    public IHttpService getHttpService()
    {
        return currentlyDisplayedItem.getHttpService();
    }


//
// extend JTable to handle cell selection
//

    private class Table extends JTable
    {
        public Table(TableModel tableModel)
        {
            super(tableModel);
        }

        @Override
        public void changeSelection(int row, int col, boolean toggle, boolean extend)
        {
            // show the log entry for the selected row
            LogEntry logEntry = log.get(row);
            requestViewer.setMessage(logEntry.requestResponse.getRequest(), true);
            responseViewer.setMessage(logEntry.requestResponse.getResponse(), false);
            currentlyDisplayedItem = logEntry.requestResponse;

            super.changeSelection(row, col, toggle, extend);
        }
    }

//
// class to hold details of each log entry
//

    private static class LogEntry
    {
        final int tool;
        final IHttpRequestResponsePersisted requestResponse;
        final URL url;

        LogEntry(int tool, IHttpRequestResponsePersisted requestResponse, URL url)
        {
            this.tool = tool;
            this.requestResponse = requestResponse;
            this.url = url;
        }
    }
}
