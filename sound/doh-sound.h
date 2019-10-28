#ifndef DOH_SOUND 
#define DOH_SOUND

#include <SDL2/SDL.h>

#define DOH_SOUND_FILE "sound/doh-sound.wav"

void my_audio_callback(void *userdata, Uint8 *stream, int len);
void *play_sound(void *args);

#endif /* DOH_SOUND */
