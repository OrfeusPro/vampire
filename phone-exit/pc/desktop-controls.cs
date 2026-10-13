using System;
using System.Collections.ObjectModel;
using System.Collections.Generic;
using System.Drawing;
using System.Runtime.InteropServices;
using System.Windows.Forms;

namespace PhoneExit {
    public static class DesktopDpi {
        [DllImport("user32.dll")] public static extern bool SetProcessDPIAware();
        [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr window);
        [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr window,int command);
        public static float Scale=1;
        public static void Enable(){SetProcessDPIAware();using(var graphics=Graphics.FromHwnd(IntPtr.Zero))Scale=graphics.DpiX/96f;}
    }

    public sealed class DesktopWindow : Form {
        public DesktopWindow(){DoubleBuffered=true;ResizeRedraw=true;}
        [StructLayout(LayoutKind.Sequential)] struct PointData {public int X,Y;}
        [StructLayout(LayoutKind.Sequential)] struct MinMaxData {public PointData Reserved,MaxSize,MaxPosition,MinTrackSize,MaxTrackSize;}
        protected override void WndProc(ref Message message){
            if(message.Msg==0x84 && WindowState==FormWindowState.Normal){
                long packed=message.LParam.ToInt64();var point=PointToClient(new Point((short)packed,(short)(packed>>16)));
                int edge=(int)Math.Ceiling(7*DesktopDpi.Scale);
                bool left=point.X<edge,right=point.X>=ClientSize.Width-edge,top=point.Y<edge,bottom=point.Y>=ClientSize.Height-edge;
                int hit=top?(left?13:right?14:12):bottom?(left?16:right?17:15):left?10:right?11:0;
                if(hit!=0){message.Result=(IntPtr)hit;return;}
            }
            base.WndProc(ref message);
            if(message.Msg==0x24){
                var bounds=Screen.FromHandle(Handle).Bounds;var work=Screen.FromHandle(Handle).WorkingArea;
                var limits=(MinMaxData)Marshal.PtrToStructure(message.LParam,typeof(MinMaxData));
                limits.MaxPosition.X=work.Left-bounds.Left;limits.MaxPosition.Y=work.Top-bounds.Top;
                limits.MaxSize.X=work.Width;limits.MaxSize.Y=work.Height;
                Marshal.StructureToPtr(limits,message.LParam,false);
            }
        }
    }

    public sealed class DarkMenuColors : ProfessionalColorTable {
        static Color Surface = Color.FromArgb(39,44,49), Selected = Color.FromArgb(52,65,59);
        public override Color ToolStripDropDownBackground { get { return Surface; } }
        public override Color MenuBorder { get { return Selected; } }
        public override Color MenuItemBorder { get { return Selected; } }
        public override Color MenuItemSelected { get { return Selected; } }
        public override Color ImageMarginGradientBegin { get { return Surface; } }
        public override Color ImageMarginGradientMiddle { get { return Surface; } }
        public override Color ImageMarginGradientEnd { get { return Surface; } }
        public override Color CheckBackground { get { return Selected; } }
        public override Color CheckSelectedBackground { get { return Selected; } }
        public override Color CheckPressedBackground { get { return Selected; } }
    }

    public sealed class DarkButton : Button {
        public string NavigationIcon {get;set;}
        protected override void OnPaint(PaintEventArgs e){
            if(!String.IsNullOrEmpty(NavigationIcon)){
                e.Graphics.Clear(BackColor);float s=DesktopDpi.Scale,x=14*s,y=Height/2f-6*s;
                using(var pen=new Pen(ForeColor,Math.Max(1,1.2f*s))){
                    if(NavigationIcon=="devices"){for(int i=0;i<4;i++)e.Graphics.DrawRectangle(pen,x+(i%2)*8*s,y+(i/2)*8*s,4*s,4*s);}
                    else if(NavigationIcon=="connection"){e.Graphics.DrawPolygon(pen,new[]{new PointF(x,y),new PointF(x+6*s,y-2*s),new PointF(x+12*s,y),new PointF(x+12*s,y+8*s),new PointF(x+6*s,y+13*s),new PointF(x,y+8*s)});}
                    else if(NavigationIcon=="bots"){e.Graphics.DrawRectangle(pen,x,y+3*s,12*s,10*s);e.Graphics.DrawLine(pen,x+6*s,y-1*s,x+6*s,y+3*s);e.Graphics.DrawRectangle(pen,x+3*s,y+6*s,1*s,1*s);e.Graphics.DrawRectangle(pen,x+8*s,y+6*s,1*s,1*s);e.Graphics.DrawLine(pen,x+4*s,y+10*s,x+8*s,y+10*s);}
                    else{for(int i=0;i<3;i++){e.Graphics.DrawLine(pen,x,y+i*5*s,x+13*s,y+i*5*s);e.Graphics.DrawLine(pen,x+(i==1?9:4)*s,y+(i*5-2)*s,x+(i==1?9:4)*s,y+(i*5+2)*s);}}
                }
                TextRenderer.DrawText(e.Graphics,Text,Font,new Rectangle((int)(36*s),0,Width-(int)(40*s),Height),ForeColor,TextFormatFlags.NoPadding|TextFormatFlags.VerticalCenter|TextFormatFlags.SingleLine|TextFormatFlags.EndEllipsis);
                if(Focused)using(var focusPen=new Pen(Color.FromArgb(98,231,188)))e.Graphics.DrawRectangle(focusPen,2,2,Width-5,Height-5);return;
            }
            if(Enabled){base.OnPaint(e);return;}
            e.Graphics.Clear(BackColor);
            TextRenderer.DrawText(e.Graphics,Text,Font,ClientRectangle,Color.FromArgb(119,136,158),BackColor,
                TextFormatFlags.HorizontalCenter|TextFormatFlags.VerticalCenter|TextFormatFlags.SingleLine|TextFormatFlags.EndEllipsis);
        }
    }

    public sealed class CaptionButton : Button {
        public string Icon {get;set;}
        public bool RestoredIcon {get;set;}
        protected override void OnPaint(PaintEventArgs e){
            base.OnPaint(e);
            float s=DesktopDpi.Scale,x=ClientSize.Width/2f,y=ClientSize.Height/2f;
            using(var pen=new Pen(ForeColor,Math.Max(1,1.2f*s))){
                if(Icon=="minimize")e.Graphics.DrawLine(pen,x-5*s,y,x+5*s,y);
                else if(Icon=="close"){
                    e.Graphics.DrawLine(pen,x-4*s,y-4*s,x+4*s,y+4*s);
                    e.Graphics.DrawLine(pen,x+4*s,y-4*s,x-4*s,y+4*s);
                }else{
                    if(RestoredIcon){
                        e.Graphics.DrawLines(pen,new[]{new PointF(x-3*s,y-3*s),new PointF(x-3*s,y-5*s),new PointF(x+5*s,y-5*s),new PointF(x+5*s,y+3*s),new PointF(x+3*s,y+3*s)});
                        e.Graphics.DrawRectangle(pen,x-5*s,y-3*s,8*s,8*s);
                    }else e.Graphics.DrawRectangle(pen,x-5*s,y-5*s,10*s,10*s);
                }
            }
        }
    }

    public sealed class DarkMenuRenderer : ToolStripProfessionalRenderer {
        public DarkMenuRenderer():base(new DarkMenuColors()){}
        protected override void OnRenderItemText(ToolStripItemTextRenderEventArgs e){
            var r=new Rectangle(e.TextRectangle.X,0,e.TextRectangle.Width,e.Item.Height);
            TextRenderer.DrawText(e.Graphics,e.Text,e.TextFont,r,e.TextColor,
                TextFormatFlags.NoPadding|TextFormatFlags.SingleLine|TextFormatFlags.VerticalCenter|TextFormatFlags.EndEllipsis);
        }
        protected override void OnRenderItemCheck(ToolStripItemImageRenderEventArgs e){
            var r=e.ImageRectangle;float scale=DesktopDpi.Scale;
            float x=r.X+r.Width/2f,y=e.Item.Height/2f;
            using(var pen=new Pen(Color.FromArgb(98,231,188),1.5f*scale))
                e.Graphics.DrawLines(pen,new[]{new PointF(x-4*scale,y),new PointF(x-scale,y+3*scale),new PointF(x+5*scale,y-4*scale)});
        }
    }

    public sealed class SearchField : UserControl {
        [DllImport("user32.dll",CharSet=CharSet.Unicode)] static extern IntPtr SendMessage(IntPtr window,int message,IntPtr value,string text);
        readonly TextBox input=new TextBox{BorderStyle=BorderStyle.None,Multiline=false,AccessibleName="Поиск по имени, персонажу, модели или стране"};
        readonly SearchClear clear=new SearchClear();
        readonly ToolTip tips=new ToolTip();
        public string Placeholder="Поиск имени, модели или страны";
        public override string Text {get{return input==null?base.Text:input.Text;}set{if(input==null)base.Text=value;else input.Text=value??"";}}
        int D(double value){return (int)Math.Round(value*DesktopDpi.Scale);}
        sealed class SearchClear : Button {
            public SearchClear(){FlatStyle=FlatStyle.Flat;FlatAppearance.BorderSize=0;AccessibleName="Очистить поиск";Cursor=Cursors.Hand;TabStop=false;}
            protected override void OnPaint(PaintEventArgs e){e.Graphics.Clear(BackColor);float s=DesktopDpi.Scale,x=Width/2f,y=Height/2f;using(var pen=new Pen(ForeColor,Math.Max(1,s))){e.Graphics.DrawLine(pen,x-3*s,y-3*s,x+3*s,y+3*s);e.Graphics.DrawLine(pen,x+3*s,y-3*s,x-3*s,y+3*s);}}
        }
        public SearchField(){SetStyle(ControlStyles.UserPaint|ControlStyles.AllPaintingInWmPaint|ControlStyles.OptimizedDoubleBuffer|ControlStyles.ResizeRedraw,true);BackColor=Color.FromArgb(32,36,40);ForeColor=Color.FromArgb(238,241,244);Controls.Add(input);Controls.Add(clear);input.BackColor=BackColor;input.ForeColor=ForeColor;clear.ForeColor=Color.FromArgb(145,155,165);clear.BackColor=BackColor;tips.SetToolTip(clear,"Очистить поиск");input.TextChanged+=(s,e)=>{OnTextChanged(EventArgs.Empty);LayoutInput();Invalidate();};input.GotFocus+=(s,e)=>Invalidate();input.LostFocus+=(s,e)=>Invalidate();input.KeyDown+=(s,e)=>{if(e.KeyCode==Keys.Escape){Clear();e.Handled=true;e.SuppressKeyPress=true;}};clear.Click+=(s,e)=>{Clear();input.Focus();};input.HandleCreated+=(s,e)=>SendMessage(input.Handle,0x1501,(IntPtr)1,Placeholder);LayoutInput();}
        public void Clear(){input.Clear();}
        void LayoutInput(){if(input==null)return;clear.Visible=input.Text.Length>0;int height=input.PreferredHeight;input.SetBounds(D(34),Math.Max(D(4),(Height-height)/2),Math.Max(1,Width-D(clear.Visible?66:46)),height);clear.SetBounds(Width-D(28),(Height-D(24))/2,D(24),D(24));}
        protected override void OnResize(EventArgs e){base.OnResize(e);LayoutInput();}
        protected override void OnFontChanged(EventArgs e){base.OnFontChanged(e);if(input!=null){input.Font=Font;LayoutInput();}}
        protected override void OnBackColorChanged(EventArgs e){base.OnBackColorChanged(e);if(input!=null)input.BackColor=BackColor;if(clear!=null)clear.BackColor=BackColor;}
        protected override void OnForeColorChanged(EventArgs e){base.OnForeColorChanged(e);if(input!=null)input.ForeColor=ForeColor;}
        protected override void OnEnter(EventArgs e){base.OnEnter(e);input.Focus();}
        protected override void OnMouseDown(MouseEventArgs e){base.OnMouseDown(e);input.Focus();}
        protected override void OnPaint(PaintEventArgs e){e.Graphics.Clear(Parent==null?BackColor:Parent.BackColor);e.Graphics.SmoothingMode=System.Drawing.Drawing2D.SmoothingMode.AntiAlias;var r=new RectangleF(1,1,Width-3,Height-3);float d=D(12);using(var path=new System.Drawing.Drawing2D.GraphicsPath()){path.AddArc(r.X,r.Y,d,d,180,90);path.AddArc(r.Right-d,r.Y,d,d,270,90);path.AddArc(r.Right-d,r.Bottom-d,d,d,0,90);path.AddArc(r.X,r.Bottom-d,d,d,90,90);path.CloseFigure();using(var brush=new SolidBrush(BackColor))e.Graphics.FillPath(brush,path);using(var pen=new Pen(input.Focused?Color.FromArgb(98,231,188):Color.FromArgb(52,57,63)))e.Graphics.DrawPath(pen,path);}float x=D(14),y=Height/2f-D(2);using(var pen=new Pen(Color.FromArgb(145,155,165),Math.Max(1,DesktopDpi.Scale))){e.Graphics.DrawEllipse(pen,x-D(4),y-D(4),D(8),D(8));e.Graphics.DrawLine(pen,x+D(3),y+D(3),x+D(8),y+D(8));}}
        protected override void Dispose(bool disposing){if(disposing)tips.Dispose();base.Dispose(disposing);}
    }

    public sealed class DarkSelect : Control {
        public Collection<string> Items { get; private set; }
        public event EventHandler SelectedIndexChanged;
        int selected = -1;
        ContextMenuStrip activeMenu;
        public int SelectedIndex {
            get { return selected; }
            set {
                if (value < -1 || value >= Items.Count) throw new ArgumentOutOfRangeException("value");
                if (selected == value) return;
                selected = value; Text = selected < 0 ? "" : Items[selected]; Invalidate();
                var handler = SelectedIndexChanged; if (handler != null) handler(this,EventArgs.Empty);
            }
        }
        public DarkSelect() {
            Items = new Collection<string>(); TabStop = true; AccessibleRole = AccessibleRole.ComboBox;
            SetStyle(ControlStyles.UserPaint | ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer | ControlStyles.Selectable,true);
            Cursor = Cursors.Hand;
        }
        int D(int value) { return (int)Math.Round(value * DesktopDpi.Scale); }
        protected override void OnPaint(PaintEventArgs e) {
            e.Graphics.Clear(BackColor);
            var text = new Rectangle(D(12),0,Math.Max(0,Width-D(46)),Height);
            TextRenderer.DrawText(e.Graphics,Text,Font,text,Enabled ? ForeColor : Color.FromArgb(157,170,188),BackColor,
                TextFormatFlags.NoPadding | TextFormatFlags.SingleLine | TextFormatFlags.VerticalCenter | TextFormatFlags.EndEllipsis);
            using(var pen = new Pen(Enabled ? ForeColor : Color.FromArgb(157,170,188),D(1))) {
                int x = Width-D(20), y = Height/2;
                e.Graphics.DrawLines(pen,new[] {new Point(x-D(4),y-D(2)),new Point(x,y+D(2)),new Point(x+D(4),y-D(2))});
            }
            // Solid strips remain inside the client area at fractional DPI scales.
            // Keep the complete outline visible while the popup owns focus.
            int border=Math.Max(1,D(1)), inset=1;
            using(var brush=new SolidBrush(Focused || activeMenu!=null ? Color.FromArgb(98,231,188) : Color.FromArgb(52,57,63))){
                e.Graphics.FillRectangle(brush,inset,inset,Width-2*inset,border);
                e.Graphics.FillRectangle(brush,inset,Height-inset-border,Width-2*inset,border);
                e.Graphics.FillRectangle(brush,inset,inset,border,Height-2*inset);
                e.Graphics.FillRectangle(brush,Width-inset-border,inset,border,Height-2*inset);
            }
        }
        void OpenMenu() {
            if(!Enabled || Items.Count == 0) return;
            if(activeMenu!=null){activeMenu.Close();return;}
            var menu = new ContextMenuStrip {ShowImageMargin=false,ShowCheckMargin=true,Font=Font,ForeColor=ForeColor,BackColor=BackColor};
            menu.MinimumSize=new Size(Width,0);
            activeMenu=menu;Invalidate();
            menu.Renderer = new DarkMenuRenderer();
            for(int i=0;i<Items.Count;i++) {
                int index = i;
                var item = new ToolStripMenuItem(Items[i]) {Checked=i==selected,ForeColor=ForeColor,BackColor=BackColor,AutoSize=false,Size=new Size(Width-D(4),D(36))};
                item.Click += (sender,args) => {SelectedIndex=index; Focus();}; menu.Items.Add(item);
            }
            menu.Closed += (sender,args) => {
                activeMenu=null;Invalidate();
                // ToolStrip is still processing the click while Closed fires.
                if(IsHandleCreated && !IsDisposed)BeginInvoke((Action)(() => menu.Dispose()));
                else menu.Dispose();
            };
            menu.Show(this,new Point(0,Height));
        }
        protected override void OnMouseDown(MouseEventArgs e) {base.OnMouseDown(e); if(e.Button==MouseButtons.Left){Focus();OpenMenu();}}
        protected override void OnKeyDown(KeyEventArgs e) {
            if(e.KeyCode==Keys.Space || e.KeyCode==Keys.Enter || e.KeyCode==Keys.F4){OpenMenu();e.Handled=true;}
            else if(e.KeyCode==Keys.Down || e.KeyCode==Keys.Up){SelectedIndex=Math.Max(0,Math.Min(Items.Count-1,selected+(e.KeyCode==Keys.Down?1:-1)));e.Handled=true;}
            base.OnKeyDown(e);
        }
        protected override bool IsInputKey(Keys key) {return key==Keys.Up || key==Keys.Down || base.IsInputKey(key);}
        protected override void OnGotFocus(EventArgs e){base.OnGotFocus(e);Invalidate();}
        protected override void OnLostFocus(EventArgs e){base.OnLostFocus(e);Invalidate();}
        protected override void Dispose(bool disposing){if(disposing && activeMenu!=null){activeMenu.Close();}base.Dispose(disposing);}
    }

    public sealed class DarkPhoneList : Control {
        public sealed class RowActionEventArgs : EventArgs { public int Index; public string Action; public RowActionEventArgs(int index,string action){Index=index;Action=action;} }
        public event EventHandler<RowActionEventArgs> RowAction;
        public bool ShowBotActions {get;set;}
        readonly Dictionary<int,string> botStates=new Dictionary<int,string>();
        readonly HashSet<int> assignedRows=new HashSet<int>();
        readonly Dictionary<int,int> settingsPositions=new Dictionary<int,int>();
        readonly Dictionary<int,string> phoneStatusTips=new Dictionary<int,string>(),providerTips=new Dictionary<int,string>();
        public void SetPhoneHeader(int index,int settingsX,string status,string provider){settingsPositions[index]=settingsX;phoneStatusTips[index]=status;providerTips[index]=provider;}
        readonly ToolTip actionTip=new ToolTip();
        string tipText="";
        static readonly string[] actionNames={"start","pause","stop","settings"};
        public int BotColumnX {get{return Width-D(14)-D(244);}}
        public void SetBotActions(int index,bool available,bool assigned,string state){if(assigned)assignedRows.Add(index);else assignedRows.Remove(index);botStates[index]=!available?"offline":!assigned?"unassigned":state;}
        public Rectangle ActionBounds(int index,int action){bool header=action==3&&settingsPositions.ContainsKey(index);return new Rectangle(header?settingsPositions[index]:BotColumnX+D(12+action*40),index*itemHeight-offset+D(header?8:57),D(32),D(28));}
        public bool ActionEnabled(int index,int action){string state;if(!botStates.TryGetValue(index,out state))state="offline";return action==3 || (state!="offline" && state!="unassigned" && state!="busy" && (action==0?state!="running"&&state!="starting":action==1?state=="running"||state=="starting"||state=="waiting":state!="stopped"));}
        void InvokeAction(int index,int action){if(!ActionEnabled(index,action))return;var h=RowAction;if(h!=null)h(this,new RowActionEventArgs(index,actionNames[action]));}
        void ActionMenu(){if(selected<0)return;var menu=new ContextMenuStrip();string[] labels={"Запустить / продолжить","Пауза","Остановить","Настройки телефона и бота"};for(int i=0;i<4;i++){if(i!=3&&!assignedRows.Contains(selected))continue;int action=i;var item=menu.Items.Add(labels[i]);item.Enabled=ActionEnabled(selected,i);item.Click+=(s,e)=>InvokeAction(selected,action);}menu.Closed+=(s,e)=>menu.Dispose();menu.Show(this,new Point(BotColumnX,Math.Max(0,selected*itemHeight-offset)));}
        public sealed class ItemCollection : Collection<object> {
            readonly DarkPhoneList owner;
            internal ItemCollection(DarkPhoneList owner){this.owner=owner;}
            protected override void InsertItem(int index,object item){base.InsertItem(index,item);owner.Changed();}
            protected override void ClearItems(){base.ClearItems();owner.selected=-1;owner.Changed();}
            protected override void RemoveItem(int index){base.RemoveItem(index);owner.selected=Math.Min(owner.selected,Count-1);owner.Changed();}
        }
        public ItemCollection Items { get; private set; }
        public event DrawItemEventHandler DrawItem;
        public event EventHandler SelectedIndexChanged;
        int selected=-1, itemHeight=80, offset, batch, dragY=-1, dragOffset;
        bool hoverScroll;
        public int ItemHeight {get{return itemHeight;}set{itemHeight=Math.Max(1,value);Changed();}}
        public int SelectedIndex {
            get{return selected;}
            set{
                if(value < -1 || value >= Items.Count) throw new ArgumentOutOfRangeException("value");
                if(value==selected)return;selected=value;
                if(value>=0 && batch==0){if(value*itemHeight<offset)offset=value*itemHeight;if((value+1)*itemHeight>offset+Height)offset=(value+1)*itemHeight-Height;}
                Changed();if(batch==0)NotifySelection();
            }
        }
        public DarkPhoneList(){
            Items=new ItemCollection(this);TabStop=true;AccessibleRole=AccessibleRole.List;
            SetStyle(ControlStyles.UserPaint | ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer | ControlStyles.Selectable,true);
        }
        int D(int value){return (int)Math.Round(value*DesktopDpi.Scale);}
        int MaxOffset {get{return Math.Max(0,Items.Count*itemHeight-Height);}}
        void NotifySelection(){var h=SelectedIndexChanged;if(h!=null)h(this,EventArgs.Empty);}
        void Changed(){if(batch>0)return;offset=Math.Max(0,Math.Min(MaxOffset,offset));Invalidate();}
        public void BeginUpdate(){batch++;}
        public void EndUpdate(){if(batch>0)batch--;Changed();if(batch==0)NotifySelection();}
        Rectangle Thumb {
            get{
                int h=Math.Min(Height,Math.Max(D(32),(int)((long)Height*Height/Math.Max(1,Items.Count*itemHeight))));
                int y=MaxOffset==0?0:(int)((long)offset*(Height-h)/MaxOffset);
                return new Rectangle(Width-D(9),y,D(6),h);
            }
        }
        protected override void OnPaint(PaintEventArgs e){
            e.Graphics.Clear(BackColor);
            int contentWidth=Width-(MaxOffset>0?D(14):0);
            for(int i=offset/itemHeight;i<Items.Count && i*itemHeight-offset<Height;i++){
                var rect=new Rectangle(0,i*itemHeight-offset,contentWidth,itemHeight);
                var handler=DrawItem;
                if(handler!=null)handler(this,new DrawItemEventArgs(e.Graphics,Font,rect,i,i==selected?DrawItemState.Selected:DrawItemState.None,ForeColor,BackColor));
                else TextRenderer.DrawText(e.Graphics,Items[i].ToString(),Font,rect,ForeColor,BackColor);
                if(ShowBotActions){
                    string[] symbols={"▶","Ⅱ","■","⚙"};
                    using(var font=new Font("Segoe UI Symbol",10))for(int a=0;a<4;a++){
                        if(a!=3&&!assignedRows.Contains(i))continue;
                        var bounds=ActionBounds(i,a);bool enabled=ActionEnabled(i,a);
                        using(var path=new System.Drawing.Drawing2D.GraphicsPath()){
                            int radius=D(6);path.AddArc(bounds.Left,bounds.Top,radius*2,radius*2,180,90);path.AddArc(bounds.Right-radius*2,bounds.Top,radius*2,radius*2,270,90);path.AddArc(bounds.Right-radius*2,bounds.Bottom-radius*2,radius*2,radius*2,0,90);path.AddArc(bounds.Left,bounds.Bottom-radius*2,radius*2,radius*2,90,90);path.CloseFigure();
                            using(var brush=new SolidBrush(Color.FromArgb(38,49,68)))e.Graphics.FillPath(brush,path);
                        }
                        TextRenderer.DrawText(e.Graphics,symbols[a],font,bounds,enabled?Color.FromArgb(98,231,188):Color.FromArgb(92,108,130),TextFormatFlags.HorizontalCenter|TextFormatFlags.VerticalCenter|TextFormatFlags.NoPadding);
                    }
                }
            }
            if(MaxOffset>0){
                using(var track=new SolidBrush(Color.FromArgb(32,36,40)))e.Graphics.FillRectangle(track,Width-D(12),0,D(12),Height);
                using(var thumb=new SolidBrush(hoverScroll || dragY>=0?Color.FromArgb(145,155,165):Color.FromArgb(78,88,94)))e.Graphics.FillRectangle(thumb,Thumb);
            }
            if(Focused && selected>=0){var r=new Rectangle(1,selected*itemHeight-offset+1,contentWidth-2,itemHeight-2);using(var p=new Pen(Color.FromArgb(98,231,188)))e.Graphics.DrawRectangle(p,r);}
        }
        protected override void OnMouseDown(MouseEventArgs e){
            base.OnMouseDown(e);if(e.Button!=MouseButtons.Left)return;Focus();
            if(MaxOffset>0 && e.X>=Width-D(14)){
                if(Thumb.Contains(e.Location)){dragY=e.Y;dragOffset=offset;Capture=true;}
                else{offset+=e.Y<Thumb.Y?-Height:Height;Changed();}
            }else{int index=(e.Y+offset)/itemHeight;if(index<Items.Count){SelectedIndex=index;if(ShowBotActions)for(int a=0;a<4;a++)if(ActionBounds(index,a).Contains(e.Location)){InvokeAction(index,a);break;}}}
        }
        protected override void OnMouseMove(MouseEventArgs e){
            if(ShowBotActions){string text="";int index=(e.Y+offset)/itemHeight;if(index<Items.Count){for(int a=0;a<4;a++)if((a==3||assignedRows.Contains(index))&&ActionBounds(index,a).Contains(e.Location)){text=new[]{"Запустить / продолжить","Пауза","Остановить","Настройки телефона и бота"}[a];break;}int rowY=e.Y+offset-index*itemHeight;if(text==""&&e.X>=D(8)&&e.X<=D(44)){if(rowY>=D(45)&&rowY<=D(69))phoneStatusTips.TryGetValue(index,out text);else if(rowY>=D(8)&&rowY<=D(40))providerTips.TryGetValue(index,out text);}}if(text!=tipText){tipText=text;actionTip.SetToolTip(this,text);}}
            base.OnMouseMove(e);hoverScroll=e.X>=Width-D(14);
            if(dragY>=0){int travel=Height-Thumb.Height;if(travel>0){offset=dragOffset+(int)((long)(e.Y-dragY)*MaxOffset/travel);Changed();}}
            else Invalidate();
        }
        protected override void OnMouseUp(MouseEventArgs e){base.OnMouseUp(e);dragY=-1;Capture=false;Invalidate();}
        protected override void OnMouseCaptureChanged(EventArgs e){base.OnMouseCaptureChanged(e);if(!Capture)dragY=-1;}
        protected override void OnMouseLeave(EventArgs e){base.OnMouseLeave(e);hoverScroll=false;Invalidate();}
        protected override void OnMouseWheel(MouseEventArgs e){base.OnMouseWheel(e);offset-=e.Delta*itemHeight/120;Changed();}
        protected override void OnResize(EventArgs e){base.OnResize(e);Changed();}
        protected override bool IsInputKey(Keys key){return key==Keys.Up || key==Keys.Down || key==Keys.Home || key==Keys.End || key==Keys.PageUp || key==Keys.PageDown || base.IsInputKey(key);}
        protected override void OnKeyDown(KeyEventArgs e){
            if(ShowBotActions&&(e.KeyCode==Keys.Apps||(e.Shift&&e.KeyCode==Keys.F10))){ActionMenu();e.Handled=true;return;}
            int next=selected;
            if(e.KeyCode==Keys.Down)next++;else if(e.KeyCode==Keys.Up)next--;
            else if(e.KeyCode==Keys.Home)next=0;else if(e.KeyCode==Keys.End)next=Items.Count-1;
            else if(e.KeyCode==Keys.PageDown)next+=Math.Max(1,Height/itemHeight);else if(e.KeyCode==Keys.PageUp)next-=Math.Max(1,Height/itemHeight);
            else{base.OnKeyDown(e);return;}
            if(Items.Count>0)SelectedIndex=Math.Max(0,Math.Min(Items.Count-1,next));e.Handled=true;
        }
        protected override void OnGotFocus(EventArgs e){base.OnGotFocus(e);Invalidate();}
        protected override void OnLostFocus(EventArgs e){base.OnLostFocus(e);Invalidate();}
        protected override void Dispose(bool disposing){if(disposing)actionTip.Dispose();base.Dispose(disposing);}
    }
}
