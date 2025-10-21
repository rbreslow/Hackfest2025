# 01 - Knowing French
We are given a challenge with a description fully in french and a subtitles file.
Here is the description:
>  Nous avons intercepté ce fichier de sous-titres d'un film. Notre équipe de renseignement pense qu'il contient des informations codées. Les dialogues semblent normaux, mais quelque chose nous dit de regarder de plus près... Le temps révèle tout, paraît-il.
Translated it becomes:
> We have intercepted this subtitle file from a movie. Our intelligence team thinks it contains coded information. The dialogues seem normal, but something tells us to look closer... Time reveals everything, it seems.

This hint tells us to look at the timestamps of the subtitle file.
One of the lines in the subtitle file is: "Les millisecondes aussi..." Which means "The milliseconds too...", that tells us to look at the milliseconds.
By only looking at the milliseconds of all the timestamps, we can decode into ASCII format to get the flag: `HF-{159753654852987123}`