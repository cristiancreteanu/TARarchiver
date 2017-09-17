#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

int octToDec (int x) {//functia transforma un numar din octal in zecimal
	int putere, dec;

	dec = 0;
	putere = 1;
	while (x != 0) {
		dec = dec + (x % 10) * putere;
		putere *= 8;
		x /= 10; 	
	}

	return dec;
}

long int decToOct (long int x) {// functia transforma un numar din zecimal in octal
        long int oct[13], i, octal, j;
        i = 0;
        octal = 0;
        while (x != 0) {//vectorul oct va retine resturile impartirii numarului la 8
                oct[i++] = x % 8;
                x /= 8;
        }

        for (j = i - 1; j >= 0; j--) {
                octal = octal * 10 + oct[j];//se formeaza numarul in octal
        }

        return octal;
}

union record {
        char charptr[512];
        struct header {
                char name[100];
                char mode[8];
                char uid[8];
                char gid[8];
                char size[12];
                char mtime[12];
                char chksum[8];
                char typeflag;
                char linkname[100];
                char magic[8];
                char uname[32];
                char gname[32];
                char devmajor[8];
                char devminor[8];
        } header;
};

int main () {

	union record record;
	char stringCitire[511], line[200], userInfo[512], str[512], *comanda, *permisiuni,
		*data, *ora, *filename, *archivename, permission[4], dim[12];
	FILE *archive, *usermap, *filels, *file;
	int owner, group, others, perm, i, suma, blocks, userID, groupID, j, bytes,
		 nrZerouri, dimensiune, space;

	memset(&record, 0, sizeof(union record));

	filels = fopen("file_ls", "rt");
	if (filels == NULL) {//se verifica daca fisierul exista
		exit(-1);
	}

	while (1) {

		fgets(stringCitire, 511, stdin);//comanda data de la tastatura
		comanda = strtok(stringCitire, " \n");//primul cuvant al stringului citit

		if (strcmp(comanda, "load") == 0) {
			archivename = strtok(NULL, " \n");//numele arhivei
			archive = fopen(archivename, "wb");//crearea arhivei - deschidere pentru citire

			while (!feof(filels)) {
				fgets(line, 512, filels);//se citeste linie cu line din fisierul file_ls
				if (feof(filels)) {
					break;
				}
				
				if (line[0] != '-') {//daca linia corespunde unui fisier care nu e un fisier obisnuit
					continue;//se trece la urmatoarea linie
				}

				//se configureaza header-ul fisierului

				permisiuni = strtok(line, " \n");//permisiuni
				owner = group = others = 0;
				if (permisiuni[1] == 'r') owner += 4;
				if (permisiuni[2] == 'w') owner += 2;
				if (permisiuni[3] == 'x') owner += 1;
				if (permisiuni[4] == 'r') group += 4;
				if (permisiuni[5] == 'w') group += 2;
				if (permisiuni[6] == 'x') group += 1;
				if (permisiuni[7] == 'r') others += 4;
				if (permisiuni[8] == 'w') others += 2;
				if (permisiuni[9] == 'x') others += 1;
				perm = owner * 100 + group * 10 + others;//integer pentru permisiuni in octal
				strcpy(record.header.mode, "0000");
				sprintf(permission, "%d", perm);//transformarea integer-ului de permisiuni in string
				strcat(record.header.mode, permission);

				strtok(NULL, " \n");

				//uname
				strcpy(record.header.uname, strtok(NULL, " \n"));

				//gname
				strcpy(record.header.gname, strtok(NULL, " \n"));

				strtok(NULL, " \n");

				data = strtok(NULL, " \n");//data
				ora = strtok(NULL, " \n");//ora
				strtok(NULL, " \n");//GMT

				//name & linkname
				strcpy(record.header.name, strtok(NULL, " \n"));
				strcpy(record.header.linkname, record.header.name);

				//size
				file = fopen(record.header.name, "rb");//se calculeaza dimensiunea fisierului
				fseek(file, 0, SEEK_END);
				dimensiune = ftell(file);
				fseek(file, 0, SEEK_SET);
				fclose(file);

				sprintf(record.header.size, "%ld", decToOct(dimensiune));
				if (strlen(record.header.size) < 11) {/*daca string-ul nu ocupa intreaga intreaga
										 				zona de memorie care i-a fost ocupata, se adauga zerouri inaintea lui*/
					nrZerouri = 11 - strlen(record.header.size);
					strcpy(dim, record.header.size);
					memset(record.header.size, 0, strlen(record.header.size));
					for (i = 0; i < nrZerouri; i++) {
						record.header.size[i] = '0';
					}
					strcat(record.header.size, dim);
					memset(dim, 0, strlen(dim));
				}

				//typeflag
				record.header.typeflag = 48;//typeflag este '0'

				//magic
				strcpy(record.header.magic, "GNUtar ");

				//devminor & devmajor
				strcpy(record.header.devminor, "");
				strcpy(record.header.devmajor, "");

				//mtime
				struct tm tm;
				tm.tm_isdst = 0;
				tm.tm_year = atoi(strtok(data, "- ")) - 1900;
				tm.tm_mon = atoi(strtok(NULL, "- ")) - 1;
				tm.tm_mday = atoi(strtok(NULL, "- "));
				tm.tm_hour = atoi(strtok(ora, ": "));
				tm.tm_min = atoi(strtok(NULL, ": "));
				tm.tm_sec = atoi(strtok(NULL, ": "));
				sprintf(record.header.mtime, "%ld", decToOct(mktime(&tm)));

				//uid & gid
				usermap = fopen("usermap.txt", "rt");/*se deschide usermap.txt pentru 
														cautarea uid si gid*/
				if (usermap == NULL) {//se verifica daca fisierul exista
					exit(-1);
				}
				while (!feof(usermap)) {
					fgets(userInfo, 512, usermap);//se citeste linie cu linie
					if (strstr(userInfo, record.header.uname) != NULL) {/*daca s-a gasit linia ce
																		 corespunde user-ului fisierului curent*/
						strstr(userInfo, record.header.uname);
						strtok(userInfo, ":");
						strtok(NULL, ":");

						userID = decToOct(atoi(strtok(NULL, ":")));//uid in octal
						sprintf(record.header.uid, "%d", userID);/*se transforma userID in string si
																	 se retine in header*/
						if (strlen(record.header.uid) < 7) {/*daca string-ul nu ocupa intreaga intreaga
															 zona de memorie care i-a fost ocupata, se adauga zerouri inaintea lui*/
							nrZerouri = 7 - strlen(record.header.uid);
							strcpy(dim, record.header.uid);
							memset(record.header.uid, 0, strlen(record.header.uid));
							for (i = 0; i < nrZerouri; i++) {
								record.header.uid[i] = '0';
							}
							strcat(record.header.uid, dim);
							memset(dim, 0, strlen(dim));
						}

						groupID = decToOct(atoi(strtok(NULL, ":")));//gid in octal
						sprintf(record.header.gid, "%d", groupID);/*se transforma groupID in string 
																	si se retine in header*/
						if (strlen(record.header.gid) < 7) {/*daca string-ul nu ocupa intreaga intreaga
															 zona de memorie care i-a fost ocupata, se adauga zerouri inaintea lui*/
							nrZerouri = 7 - strlen(record.header.gid);
							strcpy(dim, record.header.gid);
							memset(record.header.gid, 0, strlen(record.header.gid));
							for (i = 0; i < nrZerouri; i++) {
								record.header.gid[i] = '0';
							}
							strcat(record.header.gid, dim);
							memset(dim, 0, strlen(dim));
						}

						break;
					}
				}
				fclose(usermap);

				//chksum
				suma = 0;//se calculeaza suma tuturor octetilor
				for (i = 0; i < 512; i++) {
					suma += record.charptr[i];
				}

				space = ' ';/*se adauga valoarea a 8 spaces, deoarece se considera ca chksum
							 este un string de 8 spaces*/
				for (i = 0; i < 8; i++) {
					suma += space;
				}

				suma = decToOct(suma);//se transforma suma din zecimal in octal
				sprintf(record.header.chksum, "%d", suma);/*se transforma suma in string
															 si se retine in header*/
				if (strlen(record.header.chksum) < 6) {/*daca string-ul nu ocupa intreaga intreaga
														 zona de memorie care i-a fost ocupata, se adauga zerouri inaintea lui*/
					nrZerouri = 6 - strlen(record.header.chksum);
					strcpy(dim, record.header.chksum);
					memset(record.header.chksum, 0, strlen(record.header.chksum));
					for (i = 0; i < nrZerouri; i++) {
						record.header.chksum[i] = '0';
					}
					strcat(record.header.chksum, dim);
					memset(dim, 0, strlen(dim));
				}
				record.header.chksum[7] = ' ';


				fwrite(&record, sizeof(union record), 1, archive);//se scrie header-ul in in arhiva
				
				file = fopen(record.header.name, "rb");
				fseek(file, 0, SEEK_END);
				dimensiune = ftell(file);
				fseek(file, 0, SEEK_SET);

				memset(&record, 0, sizeof(union record));

				//se adauga continutul fisierului in arhiva

				while (!feof(file)) {//cat timp fisierul nu s a terminat
					if (dimensiune > 512) {
						fread(&record, sizeof(union record), 1, file);//se citesc cate 512 octeti
						fwrite(&record, sizeof(union record), 1, archive);//si se scriu in arhiva
						dimensiune -= 512;
					} else {//daca lungimea ultimului string este mai mica decat 512
						memset(&record, 0, sizeof(union record));/*se seteaza la 0 fiecare byte din
																	 uniunea record*/
						fread(&record, sizeof(union record), 1, file);
						fwrite(&record, sizeof(union record), 1, archive);
						break;
					}
				}

				fclose(file);
				memset(record.charptr, 0, sizeof(record.charptr));
			}
			
			fclose(archive);

		} else if (strcmp(comanda, "list") == 0) {
			archivename = strtok(NULL, " \n");
			archive = fopen(archivename, "rb");

			while (!feof(archive)) {//se parcurge arhiva pana la sfarsit
				fread(&record, sizeof(union record), 1, archive);
				if (feof(archive)) {
					break;
				}
				printf("%s\n", record.header.name);//se afiseaza numele fisierului 

				//se omit record-urile care contin datele din fisier
				blocks = octToDec(atoi(record.header.size));
				for (i = 1; i <=  blocks / 512 + 1; i++) {
					memset(record.charptr,0,sizeof(record.charptr));
					fread(&record, sizeof(union record), 1, archive);
				}
				memset(record.charptr,0,sizeof(record.charptr));
			}

			fclose(archive);

		} else if (strcmp(comanda, "get") == 0) {
			archivename = strtok(NULL, " \n");
			archive = fopen(archivename, "rb");

			filename = strtok(NULL, " \n");

			while (!feof(archive)) {
				fread(&record, sizeof(union record), 1, archive);
				if (strcmp(filename, record.header.name) != 0) {/*se citeste din arhiva pana se
																 gaseste header-ul fisierului cautat*/
					continue;
				}

				blocks = octToDec(atoi(record.header.size));/*se salveaza dimensiunea fisierului
																 in variabila blocks*/
				bytes = blocks;

				for (i = 1; i <= blocks / 512 + 1; i++) {
					if (bytes > 512) {//daca numarul de octeti ramasi este mai mare decat 512
						fread(str, sizeof(char), 512, archive);//se citesc 512 octeti din arhiva
						bytes -= 512;

						for (j = 0; j < 512; j++) {
							printf("%c", str[j]);//se afiseaza fiecare caracter in parte din string
						}
					} else {//daca numarul de octeti ramasi e mai mic decat 512
						memset(str, 0, 512);
						fread(str, sizeof(char), bytes, archive);//se citesc doar octetii ramasi din arhiva

						for (j = 0; j < bytes; j++) {
							printf("%c", str[j]);//se afiseaza fiecare caracter in parte din string
						}
						break;
					}


				}
			}

			fclose(archive);
		} else {
			return 0;
		}
	}

	fclose(filels);

	return 0;
}