��    �        �         �
     �
      �
       �     }   �     M  B  Y     �     �     �     �     �  	   �     �      �  "     9   <  :   v  F   �  "   �       (   5  G   ^     �  �  �     5     D  	   M     W     e     k     z  �   �  �   ?  �   �  �  �  	   E  
   O  �   Z  �  �  �  �  �   ^  �   �     �  !   �  G   �  /   4  �  d          *  
   ;     F     Z     l     t     |  +   �     �  1   �     �     �  
             0     B     S     c     r     �     �     �     �     �     �     �     �    �  ,   "  �  ="    �$    �%  .   �&  X   '  |  f'  �   �(  
  �)  �   �*     n+  !   {+  ,   �+  �   �+     \,  	   p,  
   z,  E   �,  *   �,  (   �,     -     +-     E-     \-  T   i-  �   �-     ?.     D.     U.  �  Y.  �   0     �0  D   �0  N   ?1  s   �1  Y   2     \2  S   a2  <   �2  *   �2  3   3  <   Q3  <   �3     �3  #   �3  P   4  :   ]4  /   �4  ,   �4  <   �4  �  25     �6  )   �6     7  �   7  �   �7     �8    �8     �9  "   �9     �9     �9     �9  	   :     :     :  %   7:  H   ]:  H   �:  t   �:  '   d;      �;  D   �;  S   �;     F<  T  L<     �=     �=  	   �=     �=     �=     �=     �=  �   �=  �   �>  �   )?  �  �?  	   NA  
   XA  _   cA  T  �A  k  C  �   �D  �   KE     	F  -   $F  U   RF  ?   �F  ~  �F     gI     yI  
   �I     �I     �I     �I     �I     �I  0   �I     J  H   J     `J  $   mJ     �J     �J     �J     �J     �J     �J     �J     K      K     5K     =K     LK     [K     cK     jK  �  �K  J   5M  �  �M  �   MO    4P  6   7Q  c   nQ  D  �Q  �   S  �   �S  �   �T     U  9   *U  A   dU  t   �U     V     -V  
   9V  j   DV  :   �V  +   �V     W  &   %W     LW     lW  b   yW  �   �W     iX     nX     X    �X  �   Z     �Z  N   �Z  Z   �Z  �   X[  ]   �[     ?\  e   D\  F   �\  6   �\  R   (]  D   {]  H   �]  #   	^  (   -^  O   V^  T   �^  D   �^  6   @_  A   w_         [       )      8      7       ]   v                 E   t   M       b   <   :   G       L              W   9   ^               "           %           ~       .          Z   &   d   >   u   *   `                  Q   w   A           h   l           p   D   V   |      =          /      m      e   I   }   Y           ,   O   H      -   X   S          N   '          x   3   a   B           !   R   #      j   c       y   $   (              ?   r   ;   6   g   \   k   f   q   C       o         �   T   U   i   
   	      1          s             _       {   n      F          0   z      +   2                       4   J   K             @      5      P    AUTHN COMPARISON AUTHN Comparison attribute value Agent contains An error occured while trying to update the login phase to LoginState::PHASE_SAML_AUTH  into the LoginState database.
                                  Review the saml log for more details An error occured while trying to update the samlResponseId into the LoginState database. Review the saml log for more details Assert saml Authentication context needs to be satisfied by the IdP in order to allow Saml login. Set
                                         to "none" and OneLogin PHPSAML will not send an AuthContext in the AuthNRequest. Or,
                                         select one or more options using the "control+click" combination. Better Bypass SAML auth COMMENTS COMPRESS REQUESTS COMPRESS RESPONSES CONFIG ID CREATE DATE Client Agent performing the call Configuration deleted successfully Configuration invalid please correct all ⭕ errors first Configuration invalid, please correct all ⭕ errors first Configuration update failed, check your update rights or error logging Configuration updated successfully Could not load loginState Could not load loginState from database! Could not update the loginState and therefor stopped the loginFlow for: DEBUG Detected a default guest user in samlResponse, this is not supported<br>
                                      by glpiSAML. Please create a dedicated account for this user owned by your
                                      tenant/identity provider.<br>
                                      Also see: https://learn.microsoft.com/en-us/azure/active-directory/develop/saml-claims-customization ENCRYPT NAMEID ENFORCED ENTITY ID Email Address Exact Excluded paths FRIENDLY NAME GLPI SAML was not able to assign the correct permissions to your user.
                                                     Please let an Administrator review them before using GLPI. GLPI SAML was not able to assign the correct permissions to your user.
                                                    Please let an Administrator review the user before using GLPI. GLPI SAML was not able to update the user defaults.
                                                     Please let an administrator review the user before using GLPI. GLPI did not expect an assertion from this Idp. The most likely reason is a race condition
                                  causing an inconsistant loginState in the database or software bug. Please login again via the
                                  GLPI-interface. Sorry for the inconvenience. See: https://codeberg.org/QuinQuies/glpisaml/wiki/LoginState.php 
                                  for more information IS ACTIVE IS DELETED Identifier of the IdP entity which is an URL provided by
                                         the SAML2 Identity Provider (IdP) If enabled PHPSAML will replace the default GLPI login screen with a version
                                                       that does not have the default GLPI login options and only allows the user to
                                                       authenticate using the configured SAML2 idps. This setting can be bypassed using
                                                       a bypass URI parameter If enabled the OneLogin PHPSAML Toolkit will reject unsigned or unencrypted
                                                       messages if it expects them to be signed or encrypted. Also it will reject the
                                                       messages if the SAML standard is not strictly followed: Destination, NameId,
                                                       Conditions are validated too. Strongly advised in production environments. If this is a valid ID. Please request your administrator to enable the 'debug' flag to expose the requested IdP config using this meta file Indicates if this configuration activated. Disabled configurations cannot be
                                                       used to login into GLPI and will NOT be shown on the login page. Installed / not configured Invalid request, redirecting back Is GLPI positioned behind a proxy that alters the SAML response scheme? Is this configuration marked as deleted by GLPI It looks like this samlResponse has already been used to authenticate a different user.
                                 Maybe an error occurred and you pressed F5 and accidently resend the samlResponse that is
                                 already registered as processed. For security reasons we can not allow processed samlResponses
                                 to be processed again. Please login again to generate a new samlResponse. Sorry for any inconvenience.
                                 If the problem presists, then please contact your administrator.
                                 See: https://codeberg.org/QuinQuies/glpisaml/wiki/LoginState.php for more information JIT USER CREATION JIT import rules LOGIN ICON LOWER CASE ENCODING MODIFICATION DATE Maximum Minimum NAMEID FORMAT NameId attribute is missing in samlResponse No Not allowed or error deleting SAML configuration! Password PasswordProtectedTransport Persistent RELAX DEST VALIDATION REQ AUTHN CONTEXT REQUESTS PROXIED SAML exclusions SAML providers SIGN AUTHN REQUEST SIGN LOGOUT REQUEST SIGN LOGOUT RESPONSE SLO URL SP CERTIFICATE SP PRIVATE KEY SSO URL STRICT Saml SSO applications SamlResponse should have at least 1 valid email address for GLPI  to find
                                          the corresponding GLPI user or create it (with JIT enabled). For this purpose make
                                          sure either the IDP provided NameId property is populated with the email address format,
                                          or configure the IDP to add the users email address in the samlResponse claims using
                                          the designated schema property key: Service provider name id is a required field Setting this value with the expected domain.tld, for example:
                                         with "google.com" will allow a user to trigger this IDP by
                                         providing their whatever@[google.com] username in the default
                                         GLPI username field. Setting this field to: youruserdomain.tld
                                         or to nothing disables this feature. Be aware that in the
                                         current implementation, configuring this field will hide
                                         the IDP button from the login screen Single Logout service endpoint of the IdP. URL Location of the IdP where
                                          SLO Request will be sent.OneLogin PHPSAML only supports
                                          the 'HTTP-redirect' binding for this endpoint. Single Sign On Service endpoint of the IdP. URL Target of the IdP where the
                                         Authentication Request Message will be sent. OneLogin PHPSAML
                                         only supports the 'HTTP-redirect' binding for this endpoint. Successfully added new GlpiSaml configuration. The FontAwesome (https://fontawesome.com/) icon to show on the button on the login page. The Public Base64 encoded x509 certificate used by the IdP. Fingerprinting
                                          can be used, but is not recommended. Fingerprinting requires you to manually
                                          alter the Saml Config array located in ConfigEntity.php and provide the
                                          required configuration options The Service Provider nameid format specifies the constraints
                                         on the name identifier to be used to represent the requested
                                         subject. The base62 encoded x509 service provider certificate. Used to sign and encrypt
                                         messages send by the service provider to the identity provider. Required for most
                                         of the security options The base62 encoded x509 service providers private key. Should match the modulus of the
                                         provided X509 service provider certificate The comments The date this config was modified The date this configuration item was created This name is shown with the login button on the login page.
                                         Try to keep this name short en to the point. To be excluded path Transient USERDOMAIN Unable to add new GlpiSaml configuration, please review error logging Unable to fetch idp configuration with id: Unique identifier for this configuration Unspecified Url contains path or file User with GlpiUserid:  VALIDATE XML Validation of the samlResponse document failed. Review the saml log for more details We did not receive the required POST/GET headers, see: https://codeberg.org/QuinQuies/glpisaml/wiki/ACS.php for more information X509 X509 CERTIFICATE Yes Your SSO login was successful but there is no matching GLPI user account and
                                                  we failed to create one dynamically using Just In Time user creation. Please
                                                  request a GLPI administrator to review the logs and correct the problem or
                                                  request the administrator to create a GLPI user manually. Your SSO login was successful but we where not able to fetch
                                              the loginState from the database and could not continue to log
                                              you into GLPI. none ⚠️ OpenSSL is not available, GLPI cant validate your certificate ⚠️ SP private key does not seem to match provided SP certificates modulus. ⚠️ Warning, do not use the 'withlove.from.donuts.nl' example certificates. They offer no additional protection. ⚠️ Will be defaulted to "No" because the provided SP certificate does not look valid! ⭕  ⭕ Certificate must be wrapped in valid BEGIN CERTIFICATE and END CERTIFICATE tags ⭕ Certificate should not contain "carriage returns" [<CR>] ⭕ Configuration icon is a required field ⭕ Identity provider entity id is a required field ⭕ Invalid IdP SSO URL, use: scheme://host.domain.tld/path/ ⭕ Invalid Idp SLO URL, use: scheme://host.domain.tld/path/ ⭕ Name is a required field ⭕ No valid X509 certificate found ⭕ Provided certificate does not like look a valid (base64 encoded) certificate ⭕ Requested authN context comparison is a required field ⭕ Requested authN context is a required field ⭕ The IdP SSO URL is a required field!<br> ⭕ Valid Idp X509 certificate is required! (base64 encoded) Project-Id-Version: PACKAGE VERSION
Report-Msgid-Bugs-To: 
PO-Revision-Date: 2024-10-08 12:48+0000
Last-Translator: Chris Gralike, 2024
Language-Team: French (https://app.transifex.com/quinquies/teams/199875/fr/)
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8
Content-Transfer-Encoding: 8bit
Language: fr
Plural-Forms: nplurals=3; plural=(n == 0 || n == 1) ? 0 : n != 0 && n % 1000000 == 0 ? 1 : 2;
 AUTHN COMPARISON Valeur de l'attribut de comparaison AUTHN L'agent contient Une erreur s'est produite lors de la tentative de mise à jour de la phase de connexion vers LoginState\:\:PHASE_SAML_AUTH dans la base de données LoginState. Consultez le journal saml pour plus de détails Une erreur s'est produite lors de la tentative de mise à jour du samlResponseId dans la base de données LoginState. Consultez le journal saml pour plus de détails Affirmer saml Le contexte d'authentification doit être satisfait par l'IdP afin de permettre la connexion Saml. Réglé sur "aucun" et OneLogin PHPSAML n'enverra pas d'AuthContext dans AuthNRequest. Ou sélectionnez une ou plusieurs options à l'aide de la combinaison "Ctrl+Clic". Mieux Contourner l'authentification SAML COMMENTS COMPRESS REQUESTS COMPRESS RESPONSES CONFIG ID CREATE DATE Agent client effectuant l'appel Configuration supprimée avec succès Configuration invalide, veuillez d'abord corriger toutes les ⭕ erreurs Configuration invalide, veuillez d'abord corriger toutes les ⭕ erreurs Échec de la mise à jour de la configuration, vérifiez vos droits de mise à jour ou la journalisation des erreurs Configuration mise à jour avec succès Impossible de charger loginState Impossible de charger loginState à partir de la base de données ! Impossible de mettre à jour le loginState et a donc arrêté le loginFlow pour\ : DEBUG Détection d'un utilisateur invité par défaut dans samlResponse, ceci n'est pas pris en charge<br> par glpiSAML. Veuillez créer un compte dédié pour cet utilisateur appartenant à votre locataire/fournisseur d'identité.<br> Voir également\ : https://learn.microsoft.com/en-us/azure/active-directory/develop/saml-claims-customization' ENCRYPT NAMEID ENFORCED ENTITY ID Adresse email Exacte Chemins exclus FRIENDLY NAME GLPI SAML n'a pas pu attribuer les bonnes autorisations à votre utilisateur. Veuillez laisser un administrateur les examiner avant d'utiliser GLPI. GLPI SAML n'a pas pu attribuer les bonnes autorisations à votre utilisateur. Veuillez laisser un administrateur examiner l'utilisateur avant d'utiliser GLPI. GLPI SAML n'a pas pu mettre à jour les paramètres par défaut de l'utilisateur. Veuillez laisser un administrateur examiner l'utilisateur avant d'utiliser GLPI. GLPI ne s'attendait pas à une affirmation de cet IdP. La raison la plus probable est une situation de concurrence critique provoquant un état de connexion incohérent dans la base de données ou un bug logiciel. Veuillez vous reconnecter via l'interface GLPI. Désolé pour le dérangement. Voir\ : https://codeberg.org/QuinQuies/glpisaml/wiki/LoginState.php pour plus d'informations IS ACTIVE IS DELETED Identifiant de l'entité IdP qui est une URL fournie par le fournisseur d'identité (IdP) SAML2 S'il est activé, PHPSAML remplacera l'écran de connexion GLPI par défaut par une version qui ne dispose pas des options de connexion GLPI par défaut et permettra uniquement à l'utilisateur de s'authentifier à l'aide des identifiants SAML2 configurés. Ce paramètre peut être contourné à l'aide d'un paramètre URI de contournement S'il est activé, le kit d'outils OneLogin PHPSAML rejettera les messages non signés ou non chiffrés s'il s'attend à ce qu'ils soient signés ou chiffrés. De plus, il rejettera les messages si le standard SAML n'est pas strictement suivi : Destination, NameId, Conditions sont également validées. Fortement conseillé dans les environnements de production. S'il s'agit d'une pièce d'identité valide. Veuillez demander à votre administrateur d'activer l'indicateur « debug » pour exposer la configuration IdP demandée à l'aide de ce méta-fichier. Indique si cette configuration est activée. Les configurations désactivées ne peuvent pas être utilisées pour se connecter à GLPI et ne seront PAS affichées sur la page de connexion. Installé / non configuré Demande invalide, redirection vers l'arrière GLPI est-il positionné derrière un proxy qui modifie le schéma de réponse SAML ? Cette configuration est-elle marquée comme supprimée par GLPI Il semble que cette samlResponse ait déjà été utilisée pour authentifier un autre utilisateur. Peut-être qu'une erreur s'est produite et que vous avez appuyé sur F5 et renvoyé accidentellement la samlResponse qui est déjà enregistrée comme traitée. Pour des raisons de sécurité, nous ne pouvons pas autoriser le traitement à nouveau des samlResponses traitées. Veuillez vous reconnecter pour générer une nouvelle samlResponse. Désolé pour tout inconvénient. Si le problème persiste, veuillez contacter votre administrateur. Voir\ : https://codeberg.org/QuinQuies/glpisaml/wiki/LoginState.php pour plus d'informations JIT USER CREATION Règles d'importation JIT LOGIN ICON LOWER CASE ENCODING MODIFICATION DATE Maximum Minimum NAMEID FORMAT L'attribut NameId est manquant dans samlResponse Non Non autorisé ou erreur lors de la suppression de la configuration SAML! Mot de passe Transport protégé par mot de passe Persistante RELAX DEST VALIDATION REQ AUTHN CONTEXT REQUESTS PROXIED Exclusions SAML Fournisseurs SAML SIGN AUTHN REQUEST SIGN LOGOUT REQUEST SIGN LOGOUT RESPONSE SLO URL SP CERTIFICATE SP PRIVATE KEY SSO URL STRICT applications SAML SSO SamlResponse doit avoir au moins 1 adresse e-mail valide pour que GLPI puisse trouver l'utilisateur GLPI correspondant ou le créer (avec JIT activé). À cette fin, assurez-vous que la propriété NameId fournie par l'IDP est renseignée avec le format d'adresse e-mail, ou configurez l'IDP pour ajouter l'adresse e-mail de l'utilisateur dans les revendications samlResponse à l'aide de la clé de propriété de schéma désignée : L’identifiant du nom du fournisseur de services est un champ obligatoire Définir cette valeur avec le domain.tld attendu, par exemple\: avec "google.com" permettra à un utilisateur de déclencher cet IDP en fournissant son nom d'utilisateur everything@[google.com] dans le champ de nom d'utilisateur GLPI par défaut. Définir ce champ sur \ : youruserdomain.tld ou sur rien désactive cette fonctionnalité. Sachez que dans l'implémentation actuelle, la configuration de ce champ masquera le bouton IDP de l'écran de connexion. Point de terminaison du service de déconnexion unique de l’IdP. URL Emplacement de l'IdP où la demande SLO sera envoyée. OneLogin PHPSAML prend uniquement en charge la liaison « HTTP-redirect » pour ce point de terminaison. Point de terminaison du service d’authentification unique de l’IdP. URL cible de l’IdP où le message de demande d’authentification sera envoyé. OneLogin PHPSAML prend uniquement en charge la liaison « HTTP-redirect » pour ce point de terminaison. Nouvelle configuration GlpiSaml ajoutée avec succès. L'icône FontAwesome (https://fontawesome.com/') à afficher sur le bouton de la page de connexion. Le certificat x509 codé en Base64 public utilisé par l'IdP. Les empreintes digitales peuvent être utilisées, mais elles ne sont pas recommandées. La prise d'empreintes digitales vous oblige à modifier manuellement le tableau Saml Config situé dans ConfigEntity.php et à fournir les options de configuration requises. Le format Nameid du fournisseur de services spécifie les contraintes sur l'identifiant de nom à utiliser pour représenter le sujet demandé. Le certificat du fournisseur de services x509 codé en base62. Utilisé pour signer et chiffrer les messages envoyés par le fournisseur de services au fournisseur d'identité. Requis pour la plupart des options de sécurité Clé privée du fournisseur de services x509 codée en base62. Doit correspondre au module du certificat du fournisseur de services X509 fourni Les commentaires La date à laquelle cette configuration a été modifiée La date à laquelle cet élément de configuration a été créé Ce nom est affiché avec le bouton de connexion sur la page de connexion. Essayez de garder ce nom court et précis. Chemin à exclure Transitoire USERDOMAIN Impossible d'ajouter une nouvelle configuration GlpiSaml, veuillez consulter la journalisation des erreurs Impossible de récupérer la configuration IDP avec id\ : Identifiant unique pour cette configuration Indéterminée L'URL contient le chemin ou le fichier Utilisateur avec GlpiUserid\ : VALIDATE XML La validation du document samlResponse a échoué. Consultez le journal saml pour plus de détails Nous n'avons pas reçu les en-têtes POST/GET requis, voir\ : https://codeberg.org/QuinQuies/glpisaml/wiki/ACS.php pour plus d'informations X509 X509 CERTIFICATE Oui Votre connexion SSO a réussi mais il n'existe aucun compte utilisateur GLPI correspondant et nous n'avons pas réussi à en créer un de manière dynamique en utilisant la création d'utilisateurs Just In Time. Veuillez demander à un administrateur GLPI d'examiner les journaux et de corriger le problème ou demander à l'administrateur de créer manuellement un utilisateur GLPI. Votre connexion SSO a réussi mais nous n'avons pas pu récupérer le loginState de la base de données et nous n'avons pas pu continuer à vous connecter à GLPI. aucune ⚠️ OpenSSL n'est pas disponible, GLPI ne peut pas valider votre certificat ⚠️ La clé privée SP ne semble pas correspondre au module des certificats SP modulus. ⚠️ Attention, n'utilisez pas les exemples de certificats 'withlove.from.donuts.nl'. Ils n'offrent aucune protection supplémentaire. ⚠️ Sera défini par défaut sur "Non" car le certificat SP fourni ne semble pas valide ! ⭕  ⭕ Le certificat doit être enveloppé dans des balises BEGIN CERTIFICATE et END CERTIFICATE valides ⭕ Le certificat ne doit pas contenir de « retours chariot » [<CR>] ⭕ L'icône de configuration est un champ obligatoire ⭕ L'identifiant de l'entité du fournisseur d'identité est un champ obligatoire ⭕ URL SSO IdP invalide, utilisez: schéma\://host.domain.tld/path/ ⭕ URL SLO Idp invalide, utilisez \ : schéma\://host.domain.tld/path/ ⭕ Le nom est un champ obligatoire ⭕ Aucun certificat X509 valide trouvé ⭕ Le certificat fourni n'a pas l'air d'un certificat valide (codé en base64) ⭕ La comparaison du contexte d'authentification demandée est un champ obligatoire ⭕ Le contexte d'authentification demandé est un champ obligatoire ⭕ L'URL SSO de l'IdP est un champ obligatoire !<br> ⭕ Un certificat Idp X509 valide est requis ! (codé en base64) 