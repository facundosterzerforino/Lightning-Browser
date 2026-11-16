/*
 * xt550-libre: list of the files this browser downloaded.
 *
 * On phones without the system "Downloads" app, this screen shows the
 * downloads this app queued with DownloadManager (an app always sees its own
 * downloads; no special permission is needed). Tap opens the file, long-press
 * deletes it. Licensed like the rest of Lightning (see LICENSE).
 */
package acr.browser.barebones.activities;

import java.util.ArrayList;

import acr.browser.barebones.R;
import android.app.AlertDialog;
import android.app.DownloadManager;
import android.app.ListActivity;
import android.content.ActivityNotFoundException;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.database.Cursor;
import android.net.Uri;
import android.os.Bundle;
import android.os.Handler;
import android.text.format.Formatter;
import android.view.View;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.ListView;
import android.widget.TextView;
import android.widget.Toast;

public class DownloadsActivity extends ListActivity {

	/** Opens this screen from the download notification. */
	public static class NotificationClick extends BroadcastReceiver {
		@Override
		public void onReceive(Context context, Intent intent) {
			if (DownloadManager.ACTION_DOWNLOAD_COMPLETE.equals(intent.getAction())) {
				Toast.makeText(context, R.string.xt550_download_done, Toast.LENGTH_SHORT).show();
				return;
			}
			Intent open = new Intent(context, DownloadsActivity.class);
			open.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
			context.startActivity(open);
		}
	}

	static final class Item {
		long id;
		String title;
		int status;
		long done;
		long total;
		String localUri;
		String mediaType;
	}

	private DownloadManager mManager;
	private final ArrayList<Item> mItems = new ArrayList<Item>();
	private ArrayAdapter<Item> mAdapter;
	private final Handler mHandler = new Handler();
	private final Runnable mRefresh = new Runnable() {
		@Override
		public void run() {
			reload();
			mHandler.postDelayed(this, 2000);
		}
	};

	@Override
	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		mManager = (DownloadManager) getSystemService(Context.DOWNLOAD_SERVICE);
		mAdapter = new ArrayAdapter<Item>(this, android.R.layout.simple_list_item_2,
				android.R.id.text1, mItems) {
			@Override
			public View getView(int position, View convertView, android.view.ViewGroup parent) {
				View v = super.getView(position, convertView, parent);
				Item it = getItem(position);
				((TextView) v.findViewById(android.R.id.text1)).setText(it.title);
				((TextView) v.findViewById(android.R.id.text2)).setText(describe(it));
				return v;
			}
		};
		setListAdapter(mAdapter);
		TextView empty = new TextView(this);
		empty.setText(R.string.xt550_no_downloads);
		empty.setPadding(24, 24, 24, 24);
		empty.setTextSize(18);
		((android.view.ViewGroup) getListView().getParent()).addView(empty);
		getListView().setEmptyView(empty);
		getListView().setOnItemLongClickListener(new AdapterView.OnItemLongClickListener() {
			@Override
			public boolean onItemLongClick(AdapterView<?> parent, View view, int position, long id) {
				confirmDelete(mItems.get(position));
				return true;
			}
		});
	}

	@Override
	protected void onResume() {
		super.onResume();
		mHandler.post(mRefresh);
	}

	@Override
	protected void onPause() {
		super.onPause();
		mHandler.removeCallbacks(mRefresh);
	}

	private void reload() {
		mItems.clear();
		Cursor c = null;
		try {
			c = mManager.query(new DownloadManager.Query());
			if (c != null) {
				int iId = c.getColumnIndexOrThrow(DownloadManager.COLUMN_ID);
				int iTitle = c.getColumnIndexOrThrow(DownloadManager.COLUMN_TITLE);
				int iStatus = c.getColumnIndexOrThrow(DownloadManager.COLUMN_STATUS);
				int iDone = c.getColumnIndexOrThrow(DownloadManager.COLUMN_BYTES_DOWNLOADED_SO_FAR);
				int iTotal = c.getColumnIndexOrThrow(DownloadManager.COLUMN_TOTAL_SIZE_BYTES);
				int iUri = c.getColumnIndexOrThrow(DownloadManager.COLUMN_LOCAL_URI);
				int iType = c.getColumnIndexOrThrow(DownloadManager.COLUMN_MEDIA_TYPE);
				while (c.moveToNext()) {
					Item it = new Item();
					it.id = c.getLong(iId);
					it.title = c.getString(iTitle);
					it.status = c.getInt(iStatus);
					it.done = c.getLong(iDone);
					it.total = c.getLong(iTotal);
					it.localUri = c.getString(iUri);
					it.mediaType = c.getString(iType);
					mItems.add(0, it); // newest first
				}
			}
		} catch (RuntimeException e) {
			// DownloadManager unavailable: show the empty list
		} finally {
			if (c != null) c.close();
		}
		mAdapter.notifyDataSetChanged();
	}

	private String describe(Item it) {
		switch (it.status) {
		case DownloadManager.STATUS_SUCCESSFUL:
			return getString(R.string.xt550_status_done, Formatter.formatFileSize(this, it.total));
		case DownloadManager.STATUS_FAILED:
			return getString(R.string.xt550_status_failed);
		case DownloadManager.STATUS_PAUSED:
			return getString(R.string.xt550_status_paused);
		case DownloadManager.STATUS_PENDING:
			return getString(R.string.xt550_status_pending);
		default:
			if (it.total > 0) {
				return getString(R.string.xt550_status_running, (int) (it.done * 100 / it.total));
			}
			return getString(R.string.xt550_status_running_unknown);
		}
	}

	@Override
	protected void onListItemClick(ListView l, View v, int position, long id) {
		Item it = mItems.get(position);
		if (it.status != DownloadManager.STATUS_SUCCESSFUL || it.localUri == null) {
			Toast.makeText(this, describe(it), Toast.LENGTH_SHORT).show();
			return;
		}
		Intent open = new Intent(Intent.ACTION_VIEW);
		open.setDataAndType(Uri.parse(it.localUri), it.mediaType);
		open.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
		try {
			startActivity(open);
		} catch (ActivityNotFoundException e) {
			Toast.makeText(this, R.string.xt550_no_app, Toast.LENGTH_LONG).show();
		}
	}

	private void confirmDelete(final Item it) {
		new AlertDialog.Builder(this)
				.setTitle(it.title)
				.setMessage(R.string.xt550_delete_question)
				.setPositiveButton(R.string.xt550_delete, new DialogInterface.OnClickListener() {
					@Override
					public void onClick(DialogInterface dialog, int which) {
						mManager.remove(it.id); // also deletes the file
						reload();
					}
				})
				.setNegativeButton(android.R.string.cancel, null)
				.show();
	}
}
