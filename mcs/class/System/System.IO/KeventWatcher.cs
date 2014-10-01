// 
// System.IO.KeventWatcher.cs: interface with osx kevent
//
// Authors:
//	Geoff Norton (gnorton@customerdna.com)
//
// (c) 2004 Geoff Norton
// Copyright 2014 Xamarin Inc
//
// Permission is hereby granted, free of charge, to any person obtaining
// a copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to
// permit persons to whom the Software is furnished to do so, subject to
// the following conditions:
// 
// The above copyright notice and this permission notice shall be
// included in all copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
// LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
// OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
// WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
//

using System;
using System.Collections;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

namespace System.IO {

    [Flags]
    enum EventFlags : ushort {
		/* Actions */
		/// <summary>
		/// add event to kq (implies enable)
		/// </summary>
        Add         = (ushort)0x0001,
		/// <summary>
		/// delete event from kq
		/// </summary>
        Delete      = (ushort)0x0002,
		/// <summary>
		/// enable event
		/// </summary>
        Enable      = (ushort)0x0004,
		/// <summary>
		/// disable event (not reported)
		/// </summary>
        Disable     = (ushort)0x0008,
		/// <summary>
		/// force <see cref="EventFlags.Error"/> on success, data == 0
		/// </summary>
		Receipt = (ushort)0x0040,

		/* Flags */

		/// <summary>
		/// only report one occurrence
		/// </summary>
        OneShot     = (ushort)0x0010,
		/// <summary>
		/// clear event state after reporting
		/// </summary>
        Clear       = (ushort)0x0020,
		/// <summary>
		/// disable event after reporting
		/// </summary>
        Dispatch    = (ushort)0x0080,
		/// <summary>
		/// filter-specific flag
		/// </summary>
        Flag0       = (ushort)0x1000,
		/// <summary>
		/// filter-specific flag
		/// </summary>
        Flag1       = (ushort)0x2000,
		/// <summary>
		/// reserved by system
		/// </summary>
        SystemFlags = (ushort)0xf000,
                        
        /* Return values. */
		/// <summary>
		/// EOF detected
		/// </summary>
        EOF         = (ushort)0x8000,
		/// <summary>
		/// error, data contains errno
		/// </summary>
        Error       = (ushort)0x4000,
    }
        
    enum EventFilter : short {
        Read = -1,
        Write = -2,
		/// <summary>
		/// attached to aio requests
		/// </summary>
        Aio = -3,
		/// <summary>
		/// attached to vnodes
		/// </summary>
        Vnode = -4,
		/// <summary>
		/// attached to struct proc
		/// </summary>
        Proc = -5,
		/// <summary>
		/// attached to struct proc
		/// </summary>
        Signal = -6,
		/// <summary>
		/// timers
		/// </summary>
        Timer = -7,
		/// <summary>
		/// Mach portsets
		/// </summary>
        MachPort = -8,
		/// <summary>
		/// Filesystem events
		/// </summary>
        FS = -9,
		/// <summary>
		/// User events
		/// </summary>
        User = -10,
		/// <summary>
		/// Audit session events
		/// </summary>
        VM = -11
    }

	enum FilterFlags : uint {
        ReadPoll          = EventFlags.Flag0,
        ReadOutOfBand     = EventFlags.Flag1,
        ReadLowWaterMark  = 0x00000001u,

        WriteLowWaterMark = ReadLowWaterMark,

        NoteTrigger       = 0x01000000u,
        NoteFFNop         = 0x00000000u,
        NoteFFAnd         = 0x40000000u,
        NoteFFOr          = 0x80000000u,
        NoteFFCopy        = 0xc0000000u,
        NoteFFCtrlMask    = 0xc0000000u,
        NoteFFlagsMask    = 0x00ffffffu,
                                  
        VNodeDelete       = 0x00000001u,
        VNodeWrite        = 0x00000002u,
        VNodeExtend       = 0x00000004u,
        VNodeAttrib       = 0x00000008u,
        VNodeLink         = 0x00000010u,
        VNodeRename       = 0x00000020u,
        VNodeRevoke       = 0x00000040u,
        VNodeNone         = 0x00000080u,
                                  
        ProcExit          = 0x80000000u,
        ProcFork          = 0x40000000u,
        ProcExec          = 0x20000000u,
        ProcReap          = 0x10000000u,
        ProcSignal        = 0x08000000u,
        ProcExitStatus    = 0x04000000u,
        ProcResourceEnd   = 0x02000000u,

        // iOS only
        ProcAppactive     = 0x00800000u,
        ProcAppBackground = 0x00400000u,
        ProcAppNonUI      = 0x00200000u,
        ProcAppInactive   = 0x00100000u,
        ProcAppAllStates  = 0x00f00000u,

        // Masks
        ProcPDataMask     = 0x000fffffu,
        ProcControlMask   = 0xfff00000u,

        VMPressure        = 0x80000000u,
        VMPressureTerminate = 0x40000000u,
        VMPressureSuddenTerminate = 0x20000000u,
        VMError           = 0x10000000u,
        TimerSeconds      =    0x00000001u,
        TimerMicroSeconds =   0x00000002u,
        TimerNanoSeconds  =   0x00000004u,
        TimerAbsolute     =   0x00000008u,
        }
			
	struct kevent : IDisposable {
		/// <summary>
		/// Value used to identify this event.
		/// The exact interpretation is determined by the attached filter, but often is a file descriptor.
		/// </summary>
		public UIntPtr ident;
		
		/// <summary>
		/// Identifies the kernel filter used to process this event.
		/// The pre-defined system filters are described below.
		/// </summary>
		public EventFilter filter;
		
		/// <summary>
		/// Actions to perform on the event.
		/// </summary>
		public EventFlags flags;
		
		/// <summary>
		/// Filter-specific flags.
		/// </summary>
		public FilterFlags fflags;
		
		/// <summary>
		/// Filter-specific data value.
		/// </summary>
		public IntPtr data;
		
		/// <summary>
		/// Opaque user-defined value passed through the kernel unchanged.
		/// </summary>
		public IntPtr udata;

		public void Dispose ()
		{
			if (udata != IntPtr.Zero)
				Marshal.FreeHGlobal (udata);
		}
	}

	unsafe struct kevent64 : IDisposable {
		/// <summary>
		/// Value used to identify this event.
		/// The exact interpretation is determined by the attached filter, but often is a file descriptor.
		/// </summary>
		public ulong ident;

		/// <summary>
		/// Identifies the kernel filter used to process this event.
		/// The pre-defined system filters are described below.
		/// </summary>
		public EventFilter filter;

		/// <summary>
		/// Actions to perform on the event.
		/// </summary>
		public EventFlags flags;

		/// <summary>
		/// Filter-specific flags.
		/// </summary>
		public FilterFlags fflags;

		/// <summary>
		/// Filter-specific data value.
		/// </summary>
		public long data;

		/// <summary>
		/// Opaque user-defined value passed through the kernel unchanged.
		/// </summary>
		public ulong udata;

		/// <summary>
		/// This field stores extensions for the event's filter.
		/// What type of extension depends on what type of filter is being used.
		/// </summary>
		public fixed ulong ext[2];

		public void Dispose()
		{
			if (udata != 0UL)
				Marshal.FreeHGlobal((IntPtr)udata);
		}
	}

	struct timespec {
		public IntPtr tv_sec;
		public IntPtr tv_usec;
	}

	class KeventFileData {
		public FileSystemInfo fsi;
		public DateTime LastAccessTime;
		public DateTime LastWriteTime;

		public KeventFileData(FileSystemInfo fsi, DateTime LastAccessTime, DateTime LastWriteTime) {
			this.fsi = fsi;
			this.LastAccessTime = LastAccessTime;
			this.LastWriteTime = LastWriteTime;
		}
	}

	class KeventData {
        public FileSystemWatcher FSW;
        public string Directory;
        public string FileMask;
        public bool IncludeSubdirs;
        public bool Enabled;
		public Hashtable DirEntries;
		public kevent ev;
    }

	class KeventWatcher : IFileWatcher
	{
		private const int c_monitorSleepTimeMilliseconds = 500;

		static bool failed;
		static KeventWatcher instance;
		static Hashtable watches;
		static Hashtable requests;
		static Thread thread;
		static int conn;
		static bool stop;
		
		private KeventWatcher ()
		{
		}
		
		// Locked by caller
		public static bool GetInstance (out IFileWatcher watcher)
		{
			if (failed == true) {
				watcher = null;
				return false;
			}

			if (instance != null) {
				watcher = instance;
				return true;
			}

			watches = Hashtable.Synchronized (new Hashtable ());
			requests = Hashtable.Synchronized (new Hashtable ());
			conn = kqueue();
			if (conn == -1) {
				failed = true;
				watcher = null;
				return false;
			}

			instance = new KeventWatcher ();
			watcher = instance;
			return true;
		}
		
		public void StartDispatching (FileSystemWatcher fsw)
		{
			KeventData data;
			lock (this) {
				if (thread == null) {
					thread = new Thread (new ThreadStart (Monitor));
					thread.IsBackground = true;
					thread.Start ();
				}

				data = (KeventData) watches [fsw];
			}

			if (data == null) {
				data = new KeventData ();
				data.FSW = fsw;
				data.Directory = fsw.FullPath;
				data.FileMask = fsw.MangledFilter;
				data.IncludeSubdirs = fsw.IncludeSubdirectories;

				data.Enabled = true;
				lock (this) {
					StartMonitoringDirectory (data);
					watches [fsw] = data;
					stop = false;
				}
			}
		}

		static void StartMonitoringDirectory (KeventData data)
		{
			DirectoryInfo dir = new DirectoryInfo (data.Directory);
			if(data.DirEntries == null) {
				data.DirEntries = new Hashtable();
				foreach (FileSystemInfo fsi in dir.GetFileSystemInfos() ) 
					data.DirEntries.Add(fsi.FullName, new KeventFileData(fsi, fsi.LastAccessTime, fsi.LastWriteTime));
			}

			int fd = open(data.Directory, 0, 0);
			if (fd > 0) {
				var ev = new kevent() {
					ident = (UIntPtr)fd,
					filter = EventFilter.Vnode,
					flags = EventFlags.Add | EventFlags.Enable | EventFlags.Clear,
					fflags =
						FilterFlags.VNodeRename |
						FilterFlags.VNodeWrite |
						FilterFlags.VNodeDelete |
						FilterFlags.VNodeAttrib,
					udata = Marshal.StringToHGlobalAuto(data.Directory)
				};
				kevent outev = new kevent();
				timespec nullts = new timespec();
				var retval = kevent(conn, ref ev, 1, ref outev, 0, ref nullts);
				if ((retval == -1) || ((ev.flags & EventFlags.Error) > 0)) {
					return;
				}
				data.ev = ev;
				requests [fd] = data;
			}
			
			if (!data.IncludeSubdirs)
				return;

		}

		public void StopDispatching (FileSystemWatcher fsw)
		{
			KeventData data;
			lock (this) {
				data = (KeventData) watches [fsw];
				if (data == null)
					return;

				StopMonitoringDirectory (data);
				watches.Remove (fsw);
				if (watches.Count == 0)
					stop = true;

				if (!data.IncludeSubdirs)
					return;

			}
		}

		static void StopMonitoringDirectory (KeventData data)
		{
			close((int)data.ev.ident.ToUInt32());
		}

		void Monitor ()
		{
			while (!stop) {
				kevent ev = new kevent();
				int haveEvents;
				lock (this) {
					// These structs aren't used for anything here,
					// but we need to pass them into the function anyway.
					var nullev = new kevent();
					var ts = new timespec();
					haveEvents = kevent (conn, ref nullev, 0, ref ev, 1, ref ts);
				}

				if (haveEvents != 0) {
					if ((haveEvents == -1) || ((ev.flags & EventFlags.Error) > 0)) {
						MonitorError ();
					} else {
						// Restart monitoring
						KeventData data = (KeventData) requests [ev.ident];
						StopMonitoringDirectory (data);
						StartMonitoringDirectory (data);
						ProcessEvent (ev);
					}
				}

				if (haveEvents > 0) {
					
				} else {
					System.Threading.Thread.Sleep(c_monitorSleepTimeMilliseconds);
				}
			}

			lock (this) {
				thread = null;
				stop = false;
			}
		}

		void MonitorError()
		{
			// Something went wrong. Stop the thread.
			lock (this) {
				stop = true;
			}
		}

		void ProcessEvent (kevent ev)
		{
			lock (this) {
				KeventData data = (KeventData) requests [ev.ident];
				if (!data.Enabled)
					return;

				FileSystemWatcher fsw;
				string filename = "";

				fsw = data.FSW;
				FileAction fa = 0;
				DirectoryInfo dir = new DirectoryInfo (data.Directory);
				FileSystemInfo changedFsi = null;

				try {
					foreach (FileSystemInfo fsi in dir.GetFileSystemInfos() )
						if (data.DirEntries.ContainsKey (fsi.FullName) && (fsi is FileInfo)) {
							KeventFileData entry = (KeventFileData) data.DirEntries [fsi.FullName];
							if (entry.LastWriteTime != fsi.LastWriteTime) {
								filename = fsi.Name;
								fa = FileAction.Modified;
								data.DirEntries [fsi.FullName] = new KeventFileData(fsi, fsi.LastAccessTime, fsi.LastWriteTime);
								if (fsw.IncludeSubdirectories && fsi is DirectoryInfo) {
									data.Directory = filename;
									requests [ev.ident] = data;
									ProcessEvent(ev);
								}
								changedFsi = fsi;
								PostEvent(filename, fsw, fa, changedFsi);
							}
						}
				} catch (Exception) {
					// The file system infos were changed while we processed them
				}
				// Deleted
				try {
					bool deleteMatched = true;
					while(deleteMatched) {
						foreach (KeventFileData entry in data.DirEntries.Values) { 
							if (!File.Exists (entry.fsi.FullName) && !Directory.Exists (entry.fsi.FullName)) {
								filename = entry.fsi.Name;
								fa = FileAction.Removed;
								data.DirEntries.Remove (entry.fsi.FullName);
								changedFsi = entry.fsi;
								PostEvent(filename, fsw, fa, changedFsi);
								break;
							}
						}
						deleteMatched = false;
					}
				} catch (Exception) {
					// The file system infos were changed while we processed them
				}
				// Added
				try {
					foreach (FileSystemInfo fsi in dir.GetFileSystemInfos()) 
						if (!data.DirEntries.ContainsKey (fsi.FullName)) {
							changedFsi = fsi;
							filename = fsi.Name;
							fa = FileAction.Added;
							data.DirEntries [fsi.FullName] = new KeventFileData(fsi, fsi.LastAccessTime, fsi.LastWriteTime);
							PostEvent(filename, fsw, fa, changedFsi);
						}
				} catch (Exception) {
					// The file system infos were changed while we processed them
				}
				

			}
		}

		private void PostEvent (string filename, FileSystemWatcher fsw, FileAction fa, FileSystemInfo changedFsi) {
			RenamedEventArgs renamed = null;
			if (fa == 0)
				return;
			
			if (fsw.IncludeSubdirectories && fa == FileAction.Added) {
				if (changedFsi is DirectoryInfo) {
					KeventData newdirdata = new KeventData ();
					newdirdata.FSW = fsw;
					newdirdata.Directory = changedFsi.FullName;
					newdirdata.FileMask = fsw.MangledFilter;
					newdirdata.IncludeSubdirs = fsw.IncludeSubdirectories;
	
					newdirdata.Enabled = true;
					lock (this) {
						StartMonitoringDirectory (newdirdata);
					}
				}
			}
		
			if (!fsw.Pattern.IsMatch(filename, true))
				return;

			lock (fsw) {
				if (changedFsi.FullName.StartsWith (fsw.FullPath, StringComparison.Ordinal)) {
					if (fsw.FullPath.EndsWith ("/", StringComparison.Ordinal)) {
						filename = changedFsi.FullName.Substring (fsw.FullPath.Length);
					} else {
						filename = changedFsi.FullName.Substring (fsw.FullPath.Length + 1);
					}
				}
				fsw.DispatchEvents (fa, filename, ref renamed);
				if (fsw.Waiting) {
					fsw.Waiting = false;
					System.Threading.Monitor.PulseAll (fsw);
				}
			}
		}

		[DllImport ("libc")]
		extern static int open(string path, int flags, int mode_t);
		
		[DllImport ("libc")]
		extern static int close(int fd);

		[DllImport ("libc", SetLastError = true)]
		extern static int kqueue();

		[DllImport("libc", SetLastError = true)]
		extern static int kevent(int kqueue, ref kevent ev, int nchanges, ref kevent evtlist,  int nevents, ref timespec ts);
	}
}


