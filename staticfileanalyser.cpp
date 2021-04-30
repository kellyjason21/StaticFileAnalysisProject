#include "staticfileanalyser.h"
#include "ui_staticfileanalyser.h"

StaticFileAnalyser::StaticFileAnalyser(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::StaticFileAnalyser)
{
    ui->setupUi(this);
}

StaticFileAnalyser::~StaticFileAnalyser()
{
    delete ui;
}
//File Listeners
//____________________________________________________________________________
void StaticFileAnalyser::on_actionOpen_triggered() {
    if(openedFile.isOpen() || ui->assemblyCode->toPlainText() != "") {
        QMessageBox::StandardButton confirmExit;
        confirmExit = QMessageBox::question(this,"Save Changes","Would you like to save your changes?",QMessageBox::Yes|QMessageBox::No);
        if(confirmExit == QMessageBox::Yes) {
            on_actionSave_triggered();
        }
    }
    QString fileToOpen;
    do {
        QString fileToOpen = QFileDialog::getOpenFileName(this,"Please Select a File to Open");
        currentFileName = fileToOpen;
        openedFile.setFileName(fileToOpen);
        if(!openedFile.open(QIODevice::ReadOnly | QFile::Text)) {
            QMessageBox::warning(this, "Warning", "Failed To Open File: " + openedFile.errorString());
        }
        QDataStream inputFileStream(&openedFile);
        setWindowTitle(currentFileName);
        quint16 fileSignatureFirstHalf;
        quint16 fileSignatureSecondHalf;
        inputFileStream >> fileSignatureFirstHalf; //Split into halves to accomodate the shorter Windows Portable Executable file signature
        inputFileStream >> fileSignatureSecondHalf;
        //printf("%016X\n",fileSignature);
        if(fileSignatureFirstHalf == 0x7f45) {
            if(fileSignatureSecondHalf == 0x4c46) {
                openedFileType = "ELF Binary";
            }
            else {
                QMessageBox::warning(this, "Warning","Error: Unknown File Type.\n\nPlease pick a valid executable file type (Portable Executable (PE) or Executable and Linkable Format (ELF)");
                openedFile.close();
                return;
            }
        }
        else if(fileSignatureFirstHalf == 0x4d5a) {
            openedFileType = "Portable Executable";
        }
        else {
            QMessageBox::warning(this, "Warning","Error: Unknown File Type.\n\nPlease pick a valid executable file type (Portable Executable (PE) or Executable and Linkable Format (ELF)");
            openedFile.close();
        }
    }
    while(!openedFile.isOpen());
    openedFile.close();
    openedFile.open(QIODevice::ReadOnly);
    return;
}



void StaticFileAnalyser::on_actionSave_triggered() {
    if(currentFileName == "New File"){
        do {
            currentFileName = QFileDialog::getSaveFileName(this, "Save As:");
            if(!currentFileName.contains(currentFileExtension,Qt::CaseInsensitive)){
                currentFileName.append(currentFileExtension);
            }
        }
        while(currentFileName == currentFileExtension);
    }
    else if(!currentFileName.contains(currentFileExtension,Qt::CaseInsensitive)) {
        currentFileName.append(currentFileExtension);
    }
    if(openedFile.isOpen()) {
        openedFile.close();
    }
    do {
        openedFile.setFileName(currentFileName);
        if(!openedFile.open(QFile::ReadWrite | QIODevice::Truncate | QFile::Text)) {
            QMessageBox::warning(this, "Warning", "Failed To Save File: " + openedFile.errorString());
        }
    }
    while(!openedFile.isOpen());
    QTextStream saveToFile(&openedFile);
    QString outputToFile = ui->assemblyCode->toPlainText();
    saveToFile << outputToFile;
    openedFile.close();
    openedFile.open(QIODevice::ReadOnly);
}

void StaticFileAnalyser::on_actionClose_triggered() {
    if(!openedFile.isOpen()) {
        QMessageBox::warning(this,"Warning","Please open a file before trying to close it");
        return;
    }
    if(ui->assemblyCode->toPlainText() != "") {
        QMessageBox::StandardButton confirmExit;
        confirmExit = QMessageBox::question(this,"Save Changes","Would you like to save your changes?",QMessageBox::Yes|QMessageBox::No);
        if(confirmExit == QMessageBox::Yes) {
            on_actionSave_triggered();
        }
    }
    ui->assemblyCode->setText("");
    this->setWindowTitle("New File");
    currentFileExtension = ".asm";
}
//____________________________________________________________________________

//____________________________________________________________________________
//Edit Listeners
void StaticFileAnalyser::on_actionEnable_Editing_toggled(bool arg1) {
    ui->assemblyCode->setEnabled(arg1);
}
//____________________________________________________________________________


//View Listeners
//____________________________________________________________________________
void StaticFileAnalyser::on_actionAscii_View_triggered() {
    if(!openedFile.isOpen()) {
        QMessageBox::warning(this, "Warning","Error: No open file! \nPlease open an executable file using the file menu before accessing this view!");
        return;
    }
    currentFileExtension = ".txt";
    QDataStream readAscii(&openedFile);
    QString asciiOutput("");
    for(int index = 0; index < openedFile.size(); index ++) {
        char currentCharacter;
        readAscii.readRawData(&currentCharacter,1);
        asciiOutput.append(currentCharacter);
    }
    ui->assemblyCode->setText(asciiOutput);
    openedFile.close();
    openedFile.open(QIODevice::ReadOnly);
    return;
}
void StaticFileAnalyser::on_actionBinary_View_triggered() {
    if(!openedFile.isOpen()) {
        QMessageBox::warning(this, "Warning","Error: No open file! \nPlease open an executable file using the file menu before accessing this view!");
        return;
    }
    currentFileExtension = ".bin";
    QDataStream readBytes(&openedFile);
    QString binaryOutput("");
    for(int index=0; index < openedFile.size(); index++) {
        char byte;
        readBytes.readRawData(&byte,1);
        std::bitset<8> bitset(byte);
        std::string printByte = bitset.to_string();
        binaryOutput.append(QString::fromStdString(printByte));
    }
    ui->assemblyCode->setText(binaryOutput);
    openedFile.close();
    openedFile.open(QIODevice::ReadOnly);
    return;
}

void StaticFileAnalyser::on_actionDisassembled_View_triggered() {
    if(!openedFile.isOpen()) {
        QMessageBox::warning(this, "Warning","Error: No open file! \nPlease open an executable file using the file menu before accessing this view!");
        return;
    }
    currentFileExtension = ".asm";
    quint8 buffer[openedFile.size()];
    QDataStream readBytes(&openedFile);
    for(int index = 0; index < openedFile.size(); index++) {
        char bufferChar;
        readBytes.readRawData(&bufferChar, 1);
        buffer[index] = bufferChar;
    }
    csh capstoneHandle;
    cs_insn* instruction;
    size_t count;
    if(cs_open(CS_ARCH_X86,CS_MODE_32,&capstoneHandle) != CS_ERR_OK) {
        QMessageBox::warning(this,"Error", "Unknown Error Occurred, Please Try Again!");
    }
    count = cs_disasm(capstoneHandle,buffer ,openedFile.size(), 0x1000, 0, &instruction);
    if(count > 0) {
        size_t j;
        for(j = 0; j < count; j++) {
            //qDebug("0x%" PRIx64 ":\t%s\t\t%s\n", instruction[j].address, instruction[j].mnemonic,instruction[j].op_str);
        }
        cs_free(instruction,count);
    }
    else {
        QMessageBox::warning(this,"Error", "Failed to disassemble the given code, please try again later!");
    }
    cs_close(&capstoneHandle);
    QString output = "";
    ui->assemblyCode->setText(output);
    openedFile.close();
    openedFile.open(QIODevice::ReadOnly);
}

void StaticFileAnalyser::on_actionFile_Properties_triggered() {
    if(!openedFile.isOpen()) {
        QMessageBox::warning(this, "Warning","Error: No open file! \nPlease open an executable file using the file menu before accessing this view!");
        return;
    }
    currentFileExtension = ".txt";
    openedFile.close();
    openedFile.open(QIODevice::ReadOnly);
    QString output = "File Type: " + openedFileType + "\nFile Size (in Bytes): " + QString::fromStdString(std::to_string(openedFile.size()));
    quint8 fileBytes[openedFile.size()];
    QDataStream readBytes(&openedFile);
    for(int index = 0; index < openedFile.size(); index++) {
        char currentByte;
        readBytes.readRawData(&currentByte,1);
        fileBytes[index] = currentByte;
    }
    double byteValueFrequencies[256];
    for (uint byteValue = 0; byteValue < 256; byteValue++) {
        int currentByteValueFrequency = 0;
        for(int index = 0; index < openedFile.size(); index++) {
            if(fileBytes[index] == byteValue) {
                currentByteValueFrequency++;
            }
        }
        byteValueFrequencies[byteValue] = float(currentByteValueFrequency) / openedFile.size();
    }
    double entropy = 0.0;
    for(int index=0; index < 256; index++) {
        if(byteValueFrequencies[index] > 0) {
            entropy += byteValueFrequencies[index] * log2(byteValueFrequencies[index]);
        }
    }
    entropy *= -1;
    output.append("\nFile Entropy: " + QString::fromStdString(std::to_string(entropy)));
    ui->assemblyCode->setText(output);
    openedFile.close();
    openedFile.open(QIODevice::ReadOnly);
    return;
}

void StaticFileAnalyser::on_actionHex_View_triggered() {
    if(!openedFile.isOpen()) {
        QMessageBox::warning(this, "Warning","Error: No open file! \nPlease open an executable file using the file menu before accessing this view!");
        return;
    }
    currentFileExtension = ".hex";
    QDataStream readAscii(&openedFile);
    QString output = "";
    for(int index = 0; index < openedFile.size(); index ++) {
        char currentCharacter, printedCharacter[3];
        readAscii.readRawData(&currentCharacter,1);
        sprintf(printedCharacter,"%02hhX",currentCharacter);
        for(int print = 0; print < 3; print++) {
            output += printedCharacter[print];
        }
        output += "\t";
    }
    ui->assemblyCode->setText(output);
    openedFile.close();
    openedFile.open(QIODevice::ReadOnly);
    return;
}

void StaticFileAnalyser::on_actionStrings_View_triggered() {
    if(!openedFile.isOpen()) {
        QMessageBox::warning(this, "Warning","Error: No open file! \nPlease open an executable file using the file menu before accessing this view!");
        return;
    }
    currentFileExtension = ".txt";
    QDataStream readAscii(&openedFile);
    QVector<QString> stringsOuput;
    QString workingString("");
    QString printableValues("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789<>;:.,/?[]{}-_=+#!£$%^&*()");
    for(int index = 0; index < openedFile.size(); index ++) {
        char currentCharacter;
        readAscii.readRawData(&currentCharacter,1);
        if(printableValues.contains(currentCharacter,Qt::CaseInsensitive)) {
            workingString.append(currentCharacter);
        }
        if(currentCharacter == '\0' && workingString.length() > 2) {
            workingString.append(currentCharacter);
            stringsOuput.append(workingString);
            workingString = "";
        }
    }
    QString finalStringsOuput("");
    for(int index = 0;index < stringsOuput.length(); index++) {
        finalStringsOuput.append(stringsOuput[index] + "\n");
    }
    ui->assemblyCode->setText(finalStringsOuput);
    openedFile.close();
    openedFile.open(QIODevice::ReadOnly);
    return;
}
void StaticFileAnalyser::on_actionMachine_View_triggered() {
    on_actionHex_View_triggered();
}

//Search Listeners
//____________________________________________________________________________
void StaticFileAnalyser::on_actionGREP_Funcitonality_triggered() {
    QTextCharFormat removeHighlighting;
    removeHighlighting.clearBackground();
    QTextCursor cursor(ui->assemblyCode->document());
    cursor.setPosition(0,QTextCursor::MoveAnchor);
    cursor.setPosition(ui->assemblyCode->toPlainText().length(),QTextCursor::KeepAnchor);
    cursor.setCharFormat(removeHighlighting);
    QRegularExpression searchExpression;
    do {
        QString searchPattern = QInputDialog::getText(this,"Enter Search Pattern","Please Enter in a Regex Pattern to Search Here:");
        searchExpression.setPattern(searchPattern);
        searchExpression.setPatternOptions(QRegularExpression::DotMatchesEverythingOption);
    }
    while(!searchExpression.isValid());
    QString currentText = ui->assemblyCode->toPlainText();
    QRegularExpressionMatchIterator resultSet = searchExpression.globalMatch(currentText);
    while(resultSet.hasNext()) {
        QRegularExpressionMatch currentMatch = resultSet.next();
        if(currentMatch.hasMatch()) {
            QString currentMatchValue = currentMatch.captured(0);
            int startOfMatch = ui->assemblyCode->toPlainText().indexOf(currentMatchValue);
            int endOfMatch = startOfMatch + currentMatchValue.length();
            QTextCharFormat highlightMatches;
            highlightMatches.setBackground(Qt::green);
            highlightMatches.setForeground(Qt::black);
            QTextCursor cursor(ui->assemblyCode->document());
            cursor.setPosition(startOfMatch,QTextCursor::MoveAnchor);
            cursor.setPosition(endOfMatch,QTextCursor::KeepAnchor);
            cursor.setCharFormat(highlightMatches);
        }
    }
}
//____________________________________________________________________________


//Windows Listeners
//____________________________________________________________________________
void StaticFileAnalyser::on_actionMinimise_triggered() {
    this->showMinimized();
}

void StaticFileAnalyser::on_actionMaximise_triggered() {
    this->showMaximized();
}

void StaticFileAnalyser::on_actionRestore_triggered() {
    this->showNormal();
}

void StaticFileAnalyser::on_actionFullscreen_triggered() {
    if(this->isFullScreen()){
        this->showNormal();
    }
    else {
        this->showFullScreen();
    }
}
//____________________________________________________________________________

//Exit Listeners
//____________________________________________________________________________
void StaticFileAnalyser::on_actionSave_and_Exit_triggered() {
    on_actionSave_triggered();
    QApplication::quit();
    //QTextStream saveToFile(&openedFile);#
    return;
}

void StaticFileAnalyser::on_actionDiscard_changes_and_Exit_triggered() {
    QMessageBox::StandardButton confirmExit;
    confirmExit = QMessageBox::question(this,"Discard Changes and Exit","Are you sure you want to exit without saving your changes?",QMessageBox::Yes|QMessageBox::No);
    if(confirmExit != QMessageBox::Yes) {
        return;
    }
    if(openedFile.isOpen()) {
        openedFile.close();
    }
    QApplication::quit();
}
//____________________________________________________________________________
