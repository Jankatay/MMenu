#include <gtk/gtk.h>
#include "./back/mmenu.h"

void initLabel(GtkWidget *label);
void bufHandler(GtkWidget *widget, gpointer data);
char asmBuf[32][64] = {""};
char asmOut[32*64] = "";
mpf_t res;


/* catppuccin colors */
const char *colors = ""
"window {"
	"background-color: #1e1e2e;"
"}"
"text, label {"
"	color: #cdd6f4;"
"}"
"entry {"
"	background-color: #11111b;"
"}"
"";

// user input 
GtkEntryBuffer *gbuff; // result buffer
GtkWidget *labelHex, *labelOct, *labelDec, *labelBin, *labelAscii, *labelAsm;
char out[255]; 

void static activate(GtkApplication *app, gpointer data) {
	/* init widgets */
	// set to NULL for now
	GtkWidget *window, *entry, *layoutUpper, *layoutLower;
	labelHex = labelOct = labelDec = labelBin = labelAscii = labelAsm = NULL;
	gbuff = gtk_entry_buffer_new("", 0);


	/* color */
	GtkCssProvider *provider = gtk_css_provider_new();
	GdkDisplay *display = gdk_display_get_default();
	//gtk_css_provider_load_from_path(provider, "./style.css");
	gtk_css_provider_load_from_string(provider, colors);
	gtk_style_context_add_provider_for_display(display, GTK_STYLE_PROVIDER(provider), GTK_STYLE_PROVIDER_PRIORITY_USER);


	/* window */
	// The main window program runs at
	window = gtk_application_window_new(app);
	gtk_window_set_title(GTK_WINDOW(window), "MMenu");
	gtk_window_set_default_size(GTK_WINDOW(window), 600, 250);


	/* layout */
	// Where buttons are on the screen.
	// at top is 5 rows. asm, input, binary, bottom.
	layoutUpper = gtk_box_new(GTK_ORIENTATION_VERTICAL, 25);
	// bottom row is 4 columns. hex, dec, oct, ascii
	layoutLower = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 20);
	// user input has padding on the sides
	gtk_window_set_child(GTK_WINDOW(window), layoutUpper);


	/* labels */
	// Text output. 
	labelHex = gtk_label_new("0x0"); 
	labelAsm = gtk_label_new(""); 
	labelBin = gtk_label_new("0b0"); 
	labelDec = gtk_label_new("0.0"); 
	labelOct = gtk_label_new("0o0"); 
	labelAscii = gtk_label_new(""); 
	gtk_widget_set_visible(labelAscii, false);
	gtk_widget_set_name(labelHex, "labelHex");
	gtk_widget_set_name(labelAsm, "labelHex");
	initLabel(labelHex);
	initLabel(labelAsm);
	initLabel(labelBin);
	initLabel(labelDec);
	initLabel(labelOct);
	initLabel(labelAscii);


	/* entry */
	// Text input.
	entry = gtk_entry_new();
	gtk_entry_set_buffer(GTK_ENTRY(entry), gbuff);
	PangoAttrList *list = pango_attr_list_new();
	gtk_widget_set_size_request(entry, 500, 50);
	gtk_entry_set_max_length(GTK_ENTRY(entry), 50);
	PangoAttribute *attr = pango_attr_size_new(36*PANGO_SCALE);
	pango_attr_list_insert(list, attr);
	gtk_entry_set_attributes(GTK_ENTRY(entry), list);
	pango_attr_list_unref(list);
	g_signal_connect(entry, "changed", G_CALLBACK(bufHandler),  NULL);


	/* Load layout */
	gtk_box_set_homogeneous(GTK_BOX(layoutLower), true);
	// bottom
	gtk_box_append(GTK_BOX(layoutLower), labelHex);
	gtk_box_append(GTK_BOX(layoutLower), labelDec);
	gtk_box_append(GTK_BOX(layoutLower), labelAscii);
	gtk_box_append(GTK_BOX(layoutLower), labelOct);
	// top
	gtk_box_append(GTK_BOX(layoutUpper), labelAsm);
	gtk_box_append(GTK_BOX(layoutUpper), entry);
	gtk_box_append(GTK_BOX(layoutUpper), layoutLower);
	gtk_box_append(GTK_BOX(layoutUpper), labelBin);

	// custom
	/* start presenting */
	gtk_window_present(GTK_WINDOW(window));
}

int main(int argc, char *argv[]) {
	initMMenu();
	mpf_init_set_d(res, 0);
	// run the app and return status.
	GtkApplication *app = gtk_application_new("org.MMenu", G_APPLICATION_DEFAULT_FLAGS);
	g_signal_connect(app, "activate", G_CALLBACK(activate), NULL);
	int status = g_application_run(G_APPLICATION(app), argc, argv);
	freeMMenu();
	return status;
}


void initLabel(GtkWidget *label){
	// prepare font size
	PangoAttrList *const list = pango_attr_list_new();
	PangoAttribute *const size = pango_attr_size_new(36*PANGO_SCALE);
	pango_attr_list_insert(list, size);
	// make label
	gtk_label_set_single_line_mode(GTK_LABEL(label), true);
	gtk_label_set_selectable(GTK_LABEL(label), true);
	gtk_label_set_attributes(GTK_LABEL(label), list);
	gtk_label_set_max_width_chars(GTK_LABEL(label), 10);
	// clean
	pango_attr_list_unref(list);
}

void bufHandler(GtkWidget *widget, gpointer data) {
	// clean
	strcpy(out, gtk_entry_buffer_get_text(gbuff));
	if(!out[0]) {
		return;
	}

	/* solve */
	bool status = getFinalOutput( out, res );
	if(mstatus || !status) {
		mstatus = ERR_OK;
		mpf_set_d(res, 0);
	} 
	gmp_snprintf(out, 255, "%.2Ff", res);

	/* fill */

	// decimal
	gtk_label_set_text(GTK_LABEL(labelDec), out);
	// binary
	mtob(res, out);
	gtk_label_set_text(GTK_LABEL(labelBin), out);
	// octal
	mtoo(res, out);
	gtk_label_set_text(GTK_LABEL(labelOct), out);
	// hex 
	mtox(res, out);
	gtk_label_set_text(GTK_LABEL(labelHex), out);
	// asm
	int len = charCodeToAsm(out, asmBuf);
	asmOut[0] = '\0';
	for(int i = 0; i < len; i++) {
		strcat(asmOut, asmBuf[i]);
		strcat(asmOut, "; ");
	}
	gtk_label_set_text(GTK_LABEL(labelAsm), asmOut);
	if(mstatus) { mstatus = ERR_OK; }
}
