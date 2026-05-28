#include <stdio.h>
#include <string.h>

// ─── STRUCTURE ───────────────────────────────────────────
struct ScanResult {
    char url[200];
    char input[200];
    int  score;
    char risk_level[20];
    int  is_phishing;
};

// ─── ARRAYS ──────────────────────────────────────────────
char keywords[6][20] = {"verify","secure","login","update","confirm","suspended"};
int  weights[6]      = { 15,      15,      10,     10,      10,       20 };

char bad_ext[4][10]  = {".xyz", ".tk", ".ml", ".cf"};

char otp_traps[4][30] = {"share otp","tell agent","give otp","send otp"};
char kyc_words[4][30] = {"kyc expired","aadhaar","pan card","kyc update"};

// ─── FUNCTION 1: SCAN URL ────────────────────────────────
void scan_url(char url[], struct ScanResult *r) {
    strcpy(r->url, url);
    r->score = 0;

    // check HTTP
    if (strncmp(url, "http://", 7) == 0)
        r->score += 20;

    // check keywords
    for (int i = 0; i < 6; i++) {
        char *found = strstr(url, keywords[i]);
        if (found != NULL)
            r->score += weights[i];
    }

    // check bad extensions
    for (int j = 0; j < 4; j++) {
        if (strstr(url, bad_ext[j]) != NULL)
            r->score += 25;
    }

    // assign risk
    if (r->score >= 60) {
        strcpy(r->risk_level, "CRITICAL");
        r->is_phishing = 1;
    } else if (r->score >= 30) {
        strcpy(r->risk_level, "MODERATE");
        r->is_phishing = 0;
    } else {
        strcpy(r->risk_level, "SAFE");
        r->is_phishing = 0;
    }
}

// ─── FUNCTION 2: SCAN EMAIL ──────────────────────────────
void scan_email(struct ScanResult *r) {
    char subject[100], sender[100], body[300];

    printf("\nCyberGuard: What is the subject line?\n");
    printf("You: "); fgets(subject, 100, stdin);

    printf("\nCyberGuard: Who sent it?\n");
    printf("You: "); fgets(sender, 100, stdin);

    printf("\nCyberGuard: What does the body say?\n");
    printf("You: "); fgets(body, 300, stdin);

    r->score = 0;

    // check subject keywords
    for (int i = 0; i < 6; i++)
        if (strstr(subject, keywords[i]) != NULL)
            r->score += weights[i];

    // check sender bad extensions
    for (int j = 0; j < 4; j++)
        if (strstr(sender, bad_ext[j]) != NULL)
            r->score += 25;

    // check body keywords
    for (int i = 0; i < 6; i++)
        if (strstr(body, keywords[i]) != NULL)
            r->score += weights[i];

    // if URL found in body scan it too
    if (strstr(body, "http") != NULL)
        r->score += 30;

    if (r->score >= 60) {
        strcpy(r->risk_level, "CRITICAL");
        r->is_phishing = 1;
    } else if (r->score >= 30) {
        strcpy(r->risk_level, "MODERATE");
        r->is_phishing = 0;
    } else {
        strcpy(r->risk_level, "SAFE");
        r->is_phishing = 0;
    }
}

// ─── FUNCTION 3: SCAN SMS ────────────────────────────────
void scan_sms(struct ScanResult *r) {
    char msg[300];
    printf("\nCyberGuard: Type out the SMS or WhatsApp message.\n");
    printf("You: "); fgets(msg, 300, stdin);

    r->score = 0;

    // check otp traps
    for (int i = 0; i < 4; i++)
        if (strstr(msg, otp_traps[i]) != NULL)
            r->score += 30;

    // check kyc words
    for (int j = 0; j < 4; j++)
        if (strstr(msg, kyc_words[j]) != NULL)
            r->score += 20;

    // check general keywords
    for (int k = 0; k < 6; k++)
        if (strstr(msg, keywords[k]) != NULL)
            r->score += weights[k];

    if (r->score >= 60) {
        strcpy(r->risk_level, "CRITICAL");
        r->is_phishing = 1;
    } else if (r->score >= 30) {
        strcpy(r->risk_level, "MODERATE");
        r->is_phishing = 0;
    } else {
        strcpy(r->risk_level, "SAFE");
        r->is_phishing = 0;
    }
}

// ─── MAIN ─────────────────────────────────────────────────
int main() {
    printf("==========================================\n");
    printf("   CYBERGUARD - Your Cyber Detective\n");
    printf("==========================================\n");

    struct ScanResult result;
    int choice;
    char again;

    do {
        printf("\nCyberGuard: What do you want me to check?\n");
        printf("  [1] A suspicious URL\n");
        printf("  [2] A suspicious Email\n");
        printf("  [3] A suspicious SMS / WhatsApp\n");
        printf("  [0] Exit\n");
        printf("You: "); scanf("%d", &choice); getchar();

        if (choice == 1) {
            char url[200];
            printf("\nCyberGuard: Paste the URL.\n");
            printf("You: "); fgets(url, 200, stdin);
            url[strcspn(url, "\n")] = 0;
            scan_url(url, &result);
        } else if (choice == 2) {
            scan_email(&result);
        } else if (choice == 3) {
            scan_sms(&result);
        } else if (choice == 0) {
            printf("\nCyberGuard: Stay safe. Goodbye.\n");
            break;
        }

        if (choice >= 1 && choice <= 3) {
            printf("\n------------------------------------------\n");
            printf("  Score : %d / 100\n", result.score);
            printf("  Risk  : %s\n", result.risk_level);
            if (result.is_phishing)
                printf("\nCyberGuard: This is a phishing attempt. Do NOT respond.\n");
            else
                printf("\nCyberGuard: Looks safe. But always stay alert.\n");
            printf("------------------------------------------\n");

            printf("\nCyberGuard: Want to check something else? (y/n)\n");
            printf("You: "); scanf("%c", &again); getchar();
        }

    } while (again == 'y' || again == 'Y');

    return 0;
}