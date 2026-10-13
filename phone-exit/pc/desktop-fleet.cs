using System;
using System.Collections.Generic;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Linq;
using System.Windows.Forms;

namespace PhoneExit {
    sealed class FleetMenuColors : ProfessionalColorTable {
        public override Color ToolStripDropDownBackground {get{return Color.FromArgb(32,36,40);}}
        public override Color MenuItemSelected {get{return Color.FromArgb(38,62,52);}}
        public override Color MenuItemBorder {get{return Color.FromArgb(38,62,52);}}
        public override Color MenuBorder {get{return Color.FromArgb(52,57,63);}}
    }
    sealed class FleetScroll : Control {
        int value, maximum, large=1, drag=-1, origin;
        public bool Horizontal;
        public event EventHandler Scroll;
        public int Maximum {get{return maximum;}set{maximum=Math.Max(0,value);}}
        public int LargeChange {get{return large;}set{large=Math.Max(1,value);}}
        public int SmallChange {get;set;}
        int Limit {get{return Math.Max(0,maximum-large+1);}}
        public int Value {get{return value;}set{this.value=Math.Max(0,Math.Min(Limit,value));Invalidate();}}
        Rectangle Thumb {get{int length=Horizontal?Width:Height;int size=Math.Min(length,Math.Max(24,(int)((long)length*large/Math.Max(1,maximum+1))));int offset=Limit==0?0:(int)((long)value*(length-size)/Limit);return Horizontal?new Rectangle(offset,2,size,Math.Max(1,Height-4)):new Rectangle(2,offset,Math.Max(1,Width-4),size);}}
        public FleetScroll(){SetStyle(ControlStyles.UserPaint|ControlStyles.AllPaintingInWmPaint|ControlStyles.OptimizedDoubleBuffer,true);TabStop=false;}
        void Change(int next){Value=next;var h=Scroll;if(h!=null)h(this,EventArgs.Empty);}
        protected override void OnPaint(PaintEventArgs e){e.Graphics.Clear(Color.FromArgb(17,19,21));using(var brush=new SolidBrush(Color.FromArgb(78,88,94)))e.Graphics.FillRectangle(brush,Thumb);}
        protected override void OnMouseDown(MouseEventArgs e){base.OnMouseDown(e);if(e.Button!=MouseButtons.Left)return;int at=Horizontal?e.X:e.Y;if(Thumb.Contains(e.Location)){drag=at;origin=value;Capture=true;}else Change(value+(at<(Horizontal?Thumb.Left:Thumb.Top)?-large:large));}
        protected override void OnMouseMove(MouseEventArgs e){base.OnMouseMove(e);int travel=Horizontal?Width-Thumb.Width:Height-Thumb.Height;if(drag>=0&&travel>0)Change(origin+(int)((long)((Horizontal?e.X:e.Y)-drag)*Limit/travel));}
        protected override void OnMouseUp(MouseEventArgs e){base.OnMouseUp(e);drag=-1;Capture=false;}
        protected override void OnMouseCaptureChanged(EventArgs e){base.OnMouseCaptureChanged(e);if(!Capture)drag=-1;}
        protected override void OnMouseWheel(MouseEventArgs e){Change(value-e.Delta*SmallChange/120);base.OnMouseWheel(e);}
    }
    public sealed class FleetPhone {
        public string Key, Name, Model, Country, BotId, BotText, BotState, ApkVersion, Group, BotVersion, BotName, VpnState, Provider;
        public int Index;
        public bool Online, Busy, Fresh, Pending;
        public Image Flag, GameIcon;
    }
    public sealed class FleetFilter {
        public string Group, Country, ApkVersion, BotVersion, BotId, State, VpnState, Query, Provider;
        public int Connection;
        public bool Matches(FleetPhone p){
            if(!String.IsNullOrEmpty(Query)&&(p.Name+" "+p.Model+" "+p.Country+" "+p.Key).IndexOf(Query,StringComparison.OrdinalIgnoreCase)<0)return false;
            if(Connection==1&&!p.Online||Connection==2&&p.Online)return false;
            if(Provider!=null&&(p.Provider??"")!=Provider)return false;
            if(Group!=null&&(p.Group??"")!=Group||Country!=null&&(p.Country??"")!=Country||ApkVersion!=null&&(p.ApkVersion??"")!=ApkVersion||BotVersion!=null&&(p.BotVersion??"")!=BotVersion||BotId!=null&&(p.BotId??"")!=BotId||VpnState!=null&&(p.VpnState??"off")!=VpnState)return false;
            return State==null||(State=="none"?String.IsNullOrEmpty(p.BotId):p.Fresh&&p.BotState==State);
        }
    }
    public sealed class FleetActionEventArgs : EventArgs {
        public readonly int Index; public readonly string Action, Key;
        public FleetActionEventArgs(int index,string action,string key){Index=index;Action=action;Key=key;}
    }
    // Rendering owns no transport state: every action carries the original directory index.
    public sealed class FleetView : Control {
        sealed class FleetAccessible : ControlAccessibleObject {
            readonly FleetView owner;
            public FleetAccessible(FleetView view):base(view){owner=view;}
            public override AccessibleRole Role {get{return AccessibleRole.List;}}
            public override int GetChildCount(){return owner.rows.Length;}
            public override AccessibleObject GetChild(int index){return index>=0&&index<owner.rows.Length?new PhoneAccessible(owner,owner.rows[index].Key):null;}
        }
        sealed class PhoneAccessible : AccessibleObject {
            readonly FleetView owner;readonly string key;
            int Index {get{return Array.FindIndex(owner.rows,p=>p.Key==key);}}
            public PhoneAccessible(FleetView view,string id){owner=view;key=id;}
            public override AccessibleObject Parent {get{return owner.AccessibilityObject;}}
            public override AccessibleRole Role {get{return AccessibleRole.ListItem;}}
            public override string Name {get{int i=Index;if(i<0)return "";var p=owner.rows[i];return p.Name+", "+p.Country+", "+p.Model+", APK "+owner.ApkText(p)+", "+(p.Online?"в сети":"не в сети")+", "+p.BotText+", поставщик "+(String.IsNullOrEmpty(p.Provider)?"не указан":p.Provider)+", группа "+(String.IsNullOrEmpty(p.Group)?"не указана":p.Group)+", бот "+p.BotName+" "+p.BotVersion+", VPN "+(p.VpnState??"off");}}
            public override Rectangle Bounds {get{int i=Index;return i<0?Rectangle.Empty:owner.RectangleToScreen(owner.CardBounds(i));}}
            public override AccessibleStates State {get{int i=Index;if(i<0)return AccessibleStates.Unavailable;return AccessibleStates.Selectable|AccessibleStates.Focusable|(owner.selected.Contains(key)?AccessibleStates.Selected:AccessibleStates.None)|(owner.Focused&&owner.focus==i?AccessibleStates.Focused:AccessibleStates.None);}}
            public override string DefaultAction {get{return "Выбрать / снять выбор";}}
            public override void DoDefaultAction(){int i=Index;if(i>=0){owner.Focus();owner.focus=i;owner.Toggle(i);}}
        }
        readonly FleetScroll scroll=new FleetScroll();
        readonly FleetScroll horizontal=new FleetScroll{Horizontal=true};
        readonly ToolTip tips=new ToolTip();
        readonly HashSet<string> selected=new HashSet<string>();
        FleetPhone[] rows=new FleetPhone[0];
        int focus=-1, columns=1, tileWidth, contentHeight;
        bool table, compact=true;
        public event EventHandler SelectionChanged;
        public event EventHandler<FleetActionEventArgs> Action;
        public float UiScale=1;
        public bool Table {get{return table;}set{table=value;LayoutTiles();Invalidate();}}
        public bool Compact {get{return compact;}set{compact=value;LayoutTiles();Invalidate();}}
        public int VisibleCount {get{return rows.Length;}}
        public int SelectedCount {get{return selected.Count;}}
        public int ScrollOffset {get{return scroll.Value;}}
        public int[] SelectedIndexes {get{return rows.Where(p=>selected.Contains(p.Key)).Select(p=>p.Index).ToArray();}}
        public string[] SelectedKeys {get{return rows.Where(p=>selected.Contains(p.Key)).Select(p=>p.Key).ToArray();}}
        public int[] ActionIndexes(string op){return rows.Where(p=>selected.Contains(p.Key)&&CanAct(p,op)).Select(p=>p.Index).ToArray();}
        public string[] ActionKeys(string op){return rows.Where(p=>selected.Contains(p.Key)&&CanAct(p,op)).Select(p=>p.Key).ToArray();}
        static readonly Color Bg=Color.FromArgb(17,19,21), Surface=Color.FromArgb(32,36,40), Line=Color.FromArgb(52,57,63), TextColor=Color.FromArgb(238,241,244), Muted=Color.FromArgb(145,155,165), Mint=Color.FromArgb(98,231,188);
        int D(double n){return (int)Math.Round(n*UiScale);}
        public FleetView(){SetStyle(ControlStyles.UserPaint|ControlStyles.AllPaintingInWmPaint|ControlStyles.OptimizedDoubleBuffer|ControlStyles.ResizeRedraw|ControlStyles.Selectable,true);BackColor=Bg;TabStop=true;AccessibleName="Устройства: карточки и выбор телефонов";Controls.Add(scroll);Controls.Add(horizontal);scroll.Scroll+=(s,e)=>Invalidate();horizontal.Scroll+=(s,e)=>Invalidate();}
        protected override AccessibleObject CreateAccessibilityInstance(){return new FleetAccessible(this);}
        protected override void OnGotFocus(EventArgs e){base.OnGotFocus(e);Invalidate();}
        protected override void OnLostFocus(EventArgs e){base.OnLostFocus(e);Invalidate();}
        public void SetPhones(FleetPhone[] phones){string key=focus>=0&&focus<rows.Length?rows[focus].Key:null;rows=phones??new FleetPhone[0];selected.IntersectWith(rows.Select(p=>p.Key));focus=key==null?-1:Array.FindIndex(rows,p=>p.Key==key);LayoutTiles();Invalidate();var h=SelectionChanged;if(h!=null)h(this,EventArgs.Empty);}
        public void SelectAll(bool value){selected.Clear();if(value)foreach(var p in rows)selected.Add(p.Key);Invalidate();var h=SelectionChanged;if(h!=null)h(this,EventArgs.Empty);}
        public void ClearSelection(){focus=-1;SelectAll(false);}
        int TileHeight {get{return D(table?60:compact||Height<D(376)?158:184);}}
        public Rectangle CardBounds(int i){int gap=table?0:D(8),height=TileHeight;return new Rectangle(table?-horizontal.Value:(i%columns)*(tileWidth+gap), (table?D(34):0)+(i/columns)*(height+gap)-scroll.Value,tileWidth,height);}
        int ViewHeight {get{return Height-(horizontal.Visible?D(12):0);}}
        void LayoutTiles(){int width=Math.Max(1,Width-D(18)), gap=table?0:D(8);columns=table?1:Math.Max(1,(width+gap)/(D(compact?126:176)+gap));tileWidth=table?Math.Max(width,D(1280)):Math.Max(1,(width-gap*(columns-1))/columns);horizontal.Visible=table&&tileWidth>width;horizontal.SetBounds(0,Height-D(12),width,D(12));horizontal.LargeChange=width;horizontal.SmallChange=D(60);horizontal.Maximum=tileWidth-1;horizontal.Value=table?horizontal.Value:0;contentHeight=(table?D(34):0)+((rows.Length+columns-1)/columns)*(TileHeight+gap);int max=Math.Max(0,contentHeight-ViewHeight);int previous=scroll.Value;scroll.SetBounds(Width-D(12),table?D(34):0,D(12),Math.Max(1,ViewHeight-(table?D(34):0)));scroll.LargeChange=Math.Max(1,ViewHeight);scroll.SmallChange=D(40);scroll.Maximum=max+scroll.LargeChange-1;scroll.Value=Math.Min(previous,max);scroll.Visible=max>0;}
        static readonly string[] headers={"Устройство / персонаж","Группа","Страна","Связь","VPN","APK","Бот / версия","Состояние","Поставщик","Действия"};
        public Rectangle ColumnBounds(int column){
            // Share the same tracks for headings and cells at every DPI and window size.
            double[] tracks={0,.20,.28,.35,.43,.49,.55,.73,.89,1};
            int available=Math.Max(1,tileWidth-D(104));
            int offset=table?horizontal.Value:0;
            if(column==9)return new Rectangle(available-offset,0,tileWidth-available,D(34));
            int left=(int)Math.Round(available*tracks[column]),right=(int)Math.Round(available*tracks[column+1]);
            return new Rectangle(left-offset,0,right-left,D(34));
        }
        Rectangle Cell(int column,Rectangle row,int inset){var r=ColumnBounds(column);return new Rectangle(r.X+D(inset),row.Y+D(15),Math.Max(1,r.Width-D(inset+6)),D(28));}
        string ApkText(FleetPhone phone){return String.IsNullOrEmpty(phone.ApkVersion)?"—":phone.ApkVersion;}
        protected override void OnResize(EventArgs e){base.OnResize(e);LayoutTiles();}
        void DrawLabel(Graphics g,string text,Font font,Rectangle r,Color color){if(r.Width>0)TextRenderer.DrawText(g,text??"",font,r,color,TextFormatFlags.NoPadding|TextFormatFlags.SingleLine|TextFormatFlags.EndEllipsis|TextFormatFlags.VerticalCenter);}
        static GraphicsPath Round(Rectangle r,int radius){var path=new GraphicsPath();int d=radius*2;path.AddArc(r.Left,r.Top,d,d,180,90);path.AddArc(r.Right-d,r.Top,d,d,270,90);path.AddArc(r.Right-d,r.Bottom-d,d,d,0,90);path.AddArc(r.Left,r.Bottom-d,d,d,90,90);path.CloseFigure();return path;}
        protected override void OnPaint(PaintEventArgs e){base.OnPaint(e);var g=e.Graphics;g.SetClip(new Rectangle(0,0,Math.Max(1,Width-D(18)),ViewHeight));g.SmoothingMode=SmoothingMode.AntiAlias;
            float fontScale=Font.Size/10f;
            using(var normal=new Font("Segoe UI",9*fontScale))using(var small=new Font("Segoe UI",8*fontScale))using(var bold=new Font("Segoe UI Semibold",9*fontScale)){
                if(rows.Length==0){DrawLabel(g,"Нет устройств по выбранным условиям",normal,new Rectangle(D(12),D(24),Width-D(32),D(36)),Muted);return;}
                for(int i=0;i<rows.Length;i++){var r=CardBounds(i);if(r.Bottom<(table?D(34):0)||r.Top>Height)continue;var p=rows[i];bool check=selected.Contains(p.Key);using(var path=Round(r,D(6)))using(var brush=new SolidBrush(check?Color.FromArgb(33,49,43):Surface))using(var pen=new Pen(check?Color.FromArgb(72,121,104):Line)){if(table){g.FillRectangle(brush,r);g.DrawLine(pen,r.Left,r.Bottom-1,r.Right,r.Bottom-1);}else{g.FillPath(brush,path);g.DrawPath(pen,path);}}if(Focused&&focus==i){using(var pen=new Pen(Mint))g.DrawRectangle(pen,r.X+D(3),r.Y+D(3),r.Width-D(6),r.Height-D(6));}
                    if(!table){var saved=g.Save();using(var path=Round(r,D(6)))using(var stripe=new SolidBrush(StatusAccent(p))){g.SetClip(path,CombineMode.Intersect);g.FillRectangle(stripe,r.X,r.Y,r.Width,D(3));}g.Restore(saved);}
                    var box=new Rectangle(r.X+D(10),r.Y+D(12),D(13),D(13));using(var pen=new Pen(check?Mint:Muted)){g.DrawRectangle(pen,box);if(check){using(var fill=new SolidBrush(Mint))g.FillRectangle(fill,box);using(var tick=new Pen(Bg,D(1.5))){g.DrawLines(tick,new[]{new Point(box.X+D(3),box.Y+D(6)),new Point(box.X+D(6),box.Y+D(9)),new Point(box.X+D(10),box.Y+D(3))});}}}
                    DrawLabel(g,p.Name,bold,new Rectangle(r.X+D(29),r.Y+D(6),table?Math.Max(1,ColumnBounds(0).Width-D(38)):r.Width-D(38),D(25)),TextColor);
                    Color state=p.Online?(p.Busy?Color.FromArgb(240,198,127):Mint):Muted;
                    if(table){
                        DrawLabel(g,p.Model,small,new Rectangle(r.X+D(29),r.Y+D(30),Math.Max(1,ColumnBounds(0).Width-D(38)),D(23)),Muted);
                        DrawLabel(g,String.IsNullOrEmpty(p.Group)?"Без группы":p.Group,small,Cell(1,r,6),Muted);
                        var country=Cell(2,r,6);if(p.Flag!=null)g.DrawImage(p.Flag,new Rectangle(country.X,r.Y+D(21),D(16),D(16)));DrawLabel(g,p.Country,small,Cell(2,r,p.Flag==null?6:28),TextColor);
                        using(var brush=new SolidBrush(state))g.FillEllipse(brush,Cell(3,r,6).X,r.Y+D(27),D(6),D(6));
                        DrawLabel(g,p.Online?(p.Busy?"Занят":"Онлайн"):"Офлайн",small,Cell(3,r,18),state);
                        DrawLabel(g,p.VpnState=="active"?"Вкл":p.VpnState=="blocked"?"Блок":"Выкл",small,Cell(4,r,6),p.VpnState=="active"?Mint:p.VpnState=="blocked"?Color.FromArgb(240,198,127):Muted);
                        DrawLabel(g,ApkText(p),small,Cell(5,r,6),Muted);
                        var bot=Cell(6,r,6);if(p.GameIcon!=null)g.DrawImage(p.GameIcon,new Rectangle(bot.X,r.Y+D(20),D(18),D(18)));
                        DrawLabel(g,String.IsNullOrEmpty(p.BotId)?"—":(p.BotName??p.BotId)+" · "+(String.IsNullOrEmpty(p.BotVersion)?"—":p.BotVersion),small,Cell(6,r,p.GameIcon==null?6:30),TextColor);
                        using(var brush=new SolidBrush(BotColor(p)))g.FillEllipse(brush,Cell(7,r,6).X,r.Y+D(27),D(6),D(6));
                        DrawLabel(g,p.Pending?"Команда…":p.BotText,small,Cell(7,r,18),BotColor(p));
                        DrawLabel(g,String.IsNullOrEmpty(p.Provider)?"Не указан":p.Provider,small,Cell(8,r,6),Muted);
                    }
                    else {using(var brush=new SolidBrush(state))g.FillEllipse(brush,r.X+D(10),r.Y+D(39),D(6),D(6));DrawLabel(g,p.Online?(p.Busy?"Занят":"В сети"):"Не в сети",small,new Rectangle(r.X+D(23),r.Y+D(31),r.Width-D(32),D(23)),state);
                        if(p.Flag!=null)g.DrawImage(p.Flag,new Rectangle(r.X+D(10),r.Y+D(61),D(16),D(16)));DrawLabel(g,p.Country+" · "+p.Model,small,new Rectangle(r.X+D(31),r.Y+D(57),r.Width-D(40),D(23)),Muted);
                        using(var pen=new Pen(Line))g.DrawLine(pen,r.X+D(10),r.Y+D(86),r.Right-D(10),r.Y+D(86));
                        if(p.GameIcon!=null)g.DrawImage(p.GameIcon,new Rectangle(r.X+D(10),r.Y+D(94),D(20),D(20)));DrawLabel(g,p.Pending?"Команда…":p.BotText,small,new Rectangle(r.X+D(p.GameIcon==null?10:36),r.Y+D(93),r.Width-D(p.GameIcon==null?20:45),D(22)),BotColor(p));DrawLabel(g,"APK "+ApkText(p),small,new Rectangle(r.X+D(10),r.Y+D(115),r.Width-D(20),D(20)),Muted);}
                    for(int a=0;a<3;a++)DrawAction(g,ActionBounds(i,a),a,p);
                }
                if(table)DrawTableHeader(g,small);
            }
        }
        void DrawTableHeader(Graphics g,Font font){using(var brush=new SolidBrush(Bg))g.FillRectangle(brush,0,0,tileWidth,D(34));for(int c=0;c<headers.Length;c++){var r=ColumnBounds(c);int inset=D(c==0?29:6);r.X+=inset;r.Width=Math.Max(1,r.Width-inset-D(6));DrawLabel(g,headers[c],font,r,Muted);}using(var pen=new Pen(Line))g.DrawLine(pen,0,D(34)-1,tileWidth,D(34)-1);}
        Color BotColor(FleetPhone p){return !p.Fresh?Muted:p.BotState=="error"?Color.FromArgb(242,141,157):p.BotState=="running"?Mint:p.BotState=="paused"?Color.FromArgb(240,198,127):TextColor;}
        Color StatusAccent(FleetPhone p){
            if(!p.Online)return Color.FromArgb(242,141,157);
            if(p.Pending)return Color.FromArgb(240,198,127);
            if(String.IsNullOrEmpty(p.BotId)||!p.Fresh)return Color.FromArgb(78,88,94);
            if(p.BotState=="error")return Color.FromArgb(242,141,157);
            if(p.BotState=="running")return Mint;
            if(p.BotState=="paused"||p.BotState=="starting"||p.BotState=="waiting")return Color.FromArgb(240,198,127);
            return Color.FromArgb(78,88,94);
        }
        public Rectangle ActionBounds(int i,int action){var r=CardBounds(i);return new Rectangle(table?r.Right-D(94)+action*D(29):r.X+D(6)+action*(r.Width-D(12))/3,table?r.Y+D(18):r.Bottom-D(25),D(26),D(22));}
        string QuickOp(FleetPhone p){return p.BotState=="running"?"pause":p.BotState=="paused"?"resume":"start";}
        bool CanAct(FleetPhone p,string op){return p.Online&&p.Fresh&&!p.Pending&&!string.IsNullOrEmpty(p.BotId)&&(op=="pause"?p.BotState=="running"||p.BotState=="starting"||p.BotState=="waiting":op=="resume"?p.BotState=="paused":op=="start"?p.BotState!="running"&&p.BotState!="starting"&&p.BotState!="paused":op=="stop"?p.BotState!="stopped":false);}
        void DrawAction(Graphics g,Rectangle r,int a,FleetPhone p){bool enabled=a>0||CanAct(p,QuickOp(p));using(var pen=new Pen(enabled?Muted:Color.FromArgb(66,73,79),D(1.3))){int x=r.X+D(7),y=r.Y+D(5);if(a==0){if(p.BotState=="running"){g.DrawLine(pen,x,y,x,y+D(10));g.DrawLine(pen,x+D(5),y,x+D(5),y+D(10));}else g.DrawPolygon(pen,new[]{new Point(x,y),new Point(x+D(8),y+D(5)),new Point(x,y+D(10))});}else if(a==1){for(int k=0;k<3;k++){g.DrawLine(pen,x,y+D(k*4),x+D(12),y+D(k*4));g.DrawLine(pen,x+D(k==1?8:4),y+D(k*4-2),x+D(k==1?8:4),y+D(k*4+2));}}else for(int k=0;k<3;k++)g.DrawEllipse(pen,x+D(k*5),y+D(4),D(1),D(1));}}
        void Emit(int i,string op){var h=Action;if(h!=null)h(this,new FleetActionEventArgs(rows[i].Index,op,rows[i].Key));}
        void Menu(int i){var p=rows[i];var menu=new ContextMenuStrip{BackColor=Surface,ForeColor=TextColor,ShowImageMargin=false,Renderer=new ToolStripProfessionalRenderer(new FleetMenuColors())};foreach(string op in new[]{"start","resume","pause","stop","settings","connect"}){string name=op=="start"?"Запустить":op=="resume"?"Продолжить":op=="pause"?"Пауза":op=="stop"?"Остановить":op=="settings"?"Настройки телефона и бота":"Подключение через телефон";var item=menu.Items.Add(name);item.Enabled=op=="settings"||op=="connect"||CanAct(p,op);string action=op,key=p.Key;item.Click+=(s,e)=>{int current=Array.FindIndex(rows,row=>row.Key==key);if(current>=0&&(action=="settings"||action=="connect"||CanAct(rows[current],action)))Emit(current,action);};}menu.Closed+=(s,e)=>menu.Dispose();menu.Show(this,new Point(CardBounds(i).X,Math.Max(0,CardBounds(i).Bottom)));}
        int Hit(Point point){if(table&&point.Y<D(34))return -1;for(int i=0;i<rows.Length;i++)if(CardBounds(i).Contains(point))return i;return -1;}
        void Toggle(int i){if(selected.Contains(rows[i].Key))selected.Remove(rows[i].Key);else selected.Add(rows[i].Key);Invalidate();var h=SelectionChanged;if(h!=null)h(this,EventArgs.Empty);}
        protected override void OnMouseDown(MouseEventArgs e){base.OnMouseDown(e);Focus();int i=Hit(e.Location);if(i<0){if(e.Button==MouseButtons.Left)ClearSelection();return;}focus=i;if(e.Button==MouseButtons.Right){Menu(i);return;}for(int a=0;a<3;a++)if(ActionBounds(i,a).Contains(e.Location)){if(a==2)Menu(i);else if(a==1)Emit(i,"settings");else if(CanAct(rows[i],QuickOp(rows[i])))Emit(i,QuickOp(rows[i]));return;}Toggle(i);}
        protected override void OnMouseDoubleClick(MouseEventArgs e){int i=Hit(e.Location);if(i>=0)Emit(i,"settings");base.OnMouseDoubleClick(e);}
        protected override void OnMouseMove(MouseEventArgs e){base.OnMouseMove(e);int i=Hit(e.Location);string tip="";if(i>=0){var p=rows[i];tip=p.Name+" · "+p.Country+" · "+p.Model+" · APK "+ApkText(p);for(int a=0;a<3;a++)if(ActionBounds(i,a).Contains(e.Location))tip=a==0?(QuickOp(p)=="pause"?"Пауза":QuickOp(p)=="resume"?"Продолжить":"Запустить"):a==1?"Настройки телефона и бота":"Другие действия";}if(tips.GetToolTip(this)!=tip)tips.SetToolTip(this,tip);}
        protected override void OnMouseWheel(MouseEventArgs e){if(table&&(ModifierKeys&Keys.Shift)!=0)horizontal.Value-=e.Delta*D(60)/120;else scroll.Value=Math.Max(0,Math.Min(Math.Max(0,contentHeight-ViewHeight),scroll.Value-e.Delta*D(60)/120));Invalidate();base.OnMouseWheel(e);}
        protected override bool IsInputKey(Keys key){return key==Keys.Left||key==Keys.Right||key==Keys.Up||key==Keys.Down||base.IsInputKey(key);}
        protected override void OnKeyDown(KeyEventArgs e){if(rows.Length==0)return;if(e.Control&&e.KeyCode==Keys.A){SelectAll(true);e.Handled=true;return;}if(focus<0)focus=0;if(e.KeyCode==Keys.Right)focus=Math.Min(rows.Length-1,focus+1);else if(e.KeyCode==Keys.Left)focus=Math.Max(0,focus-1);else if(e.KeyCode==Keys.Down)focus=Math.Min(rows.Length-1,focus+columns);else if(e.KeyCode==Keys.Up)focus=Math.Max(0,focus-columns);else if(e.KeyCode==Keys.Home)focus=0;else if(e.KeyCode==Keys.End)focus=rows.Length-1;else if(e.KeyCode==Keys.Space)Toggle(focus);else if(e.KeyCode==Keys.Enter)Emit(focus,"settings");else{base.OnKeyDown(e);return;}var r=CardBounds(focus);if(r.Top<(table?D(34):0))scroll.Value=Math.Max(0,scroll.Value+r.Top-(table?D(34):0));else if(r.Bottom>Height)scroll.Value=Math.Min(Math.Max(0,contentHeight-Height),scroll.Value+r.Bottom-Height);e.Handled=true;Invalidate();}
        protected override void Dispose(bool disposing){if(disposing)tips.Dispose();base.Dispose(disposing);}
    }
}
